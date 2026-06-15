package devices

import (
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"pdp/models"
	"pdp/pa/audit"
	"pdp/pa/events"
	"pdp/store"
)

var (
	ErrServiceUnavailable = errors.New("device data service is not available")
	ErrDeviceIDRequired   = errors.New("device_id is required")
	ErrDeviceIDMismatch   = errors.New("device_id does not match certificate identity")
	ErrNoPriorDeviceData  = errors.New("no prior device data report on file")
)

type EventPublisher interface {
	PublishCAEPEvent(eventType string, fields map[string]string)
}

type Service struct {
	store *store.Store
	audit *audit.AuditLogger
	now   func() time.Time

	publisherMu sync.RWMutex
	publisher   EventPublisher
}

func NewService(store *store.Store, audit *audit.AuditLogger) *Service {
	return &Service{
		store: store,
		audit: audit,
		now:   time.Now,
	}
}

func (service *Service) SetEventPublisher(publisher EventPublisher) {
	if service == nil {
		return
	}
	service.publisherMu.Lock()
	service.publisher = publisher
	service.publisherMu.Unlock()
}

func (service *Service) RecordDeviceData(report *models.DeviceDataReport) {
	service.RecordDeviceDataWithSourceIP(report, "")
}

func (service *Service) RecordDeviceDataWithSourceIP(report *models.DeviceDataReport, sourceIP string) {
	if service == nil || service.store == nil || report == nil {
		return
	}
	service.store.SaveDeviceData(report)
	if service.audit != nil {
		service.audit.LogEvent("device_data_report", "", "", strings.TrimSpace(sourceIP), report.DeviceID,
			"", "Device data received", true)
	}
	log.Printf("[PA] Device data report received: device=%s checks=%d", report.DeviceID, len(report.Checks))
}

func (service *Service) AcceptDeviceDataReport(certDeviceID string, report models.DeviceDataReport) (models.DeviceDataReport, error) {
	return service.AcceptDeviceDataReportWithSourceIP(certDeviceID, report, "")
}

func (service *Service) AcceptDeviceDataReportWithSourceIP(certDeviceID string, report models.DeviceDataReport, sourceIP string) (models.DeviceDataReport, error) {
	if err := service.ready(); err != nil {
		return report, err
	}
	certDeviceID = strings.TrimSpace(certDeviceID)
	report.DeviceID = strings.TrimSpace(report.DeviceID)
	if report.DeviceID == "" {
		return report, ErrDeviceIDRequired
	}
	if report.DeviceID != certDeviceID {
		log.Printf("[PA] Device data report rejected: device_id=%q does not match cert CN=%q", report.DeviceID, certDeviceID)
		return report, ErrDeviceIDMismatch
	}
	report.ReportedAt = service.nowTime().UTC()
	if report.CollectedAt.IsZero() {
		report.CollectedAt = report.ReportedAt
	} else {
		report.CollectedAt = report.CollectedAt.UTC()
	}
	service.RecordDeviceDataWithSourceIP(&report, sourceIP)
	service.publish(events.TopicHealthChanged, map[string]string{
		"device_id":       report.DeviceID,
		"organization_id": report.OrganizationID,
		"reason":          "device_data_reported",
	})
	return report, nil
}

func (service *Service) TouchDeviceDataHeartbeat(deviceID string) (time.Time, error) {
	if err := service.ready(); err != nil {
		return time.Time{}, err
	}
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" {
		return time.Time{}, ErrDeviceIDRequired
	}
	now := service.nowTime().UTC()
	if !service.store.TouchDeviceData(deviceID, now) {
		return now, ErrNoPriorDeviceData
	}
	service.publish(events.TopicHealthChanged, map[string]string{
		"device_id": deviceID,
		"reason":    "device_data_heartbeat",
	})
	return now, nil
}

func (service *Service) ready() error {
	if service == nil || service.store == nil {
		return ErrServiceUnavailable
	}
	return nil
}

func (service *Service) nowTime() time.Time {
	if service == nil || service.now == nil {
		return time.Now()
	}
	return service.now()
}

func (service *Service) publish(eventType string, fields map[string]string) {
	if service == nil {
		return
	}
	service.publisherMu.RLock()
	publisher := service.publisher
	service.publisherMu.RUnlock()
	if publisher != nil {
		publisher.PublishCAEPEvent(eventType, fields)
	}
}
