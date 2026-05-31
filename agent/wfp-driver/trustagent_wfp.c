#include <initguid.h>
#include "trustagent_wfp.h"

#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT 10
#endif

#define TRUSTAGENT_IPV4_LOOPBACK 0x7F000001u
#define TRUSTAGENT_CGNAT_BASE    0x64400000u
#define TRUSTAGENT_CGNAT_MASK    0xFFC00000u
#define TRUSTAGENT_TCP_PROTOCOL  6

static const GUID TRUSTAGENT_WFP_PROVIDER_KEY =
{ 0x63d5b615, 0x3845, 0x477e, { 0xb7, 0x95, 0x89, 0x7f, 0x22, 0x86, 0xea, 0x0d } };

static const GUID TRUSTAGENT_WFP_SUBLAYER_KEY =
{ 0xa39863e8, 0x4a36, 0x46e8, { 0xa6, 0xa8, 0x3e, 0xaa, 0x3b, 0xee, 0x6a, 0x12 } };

static const GUID TRUSTAGENT_WFP_CALLOUT_CONNECT_V4_KEY =
{ 0xf3d09a6e, 0x2a89, 0x4fd9, { 0x8e, 0x7d, 0x9d, 0x6b, 0x46, 0x88, 0x4f, 0x11 } };

static const GUID TRUSTAGENT_WFP_FILTER_CONNECT_V4_KEY =
{ 0x889a3f61, 0x73ad, 0x4276, { 0x89, 0xf5, 0xd7, 0x6a, 0x9f, 0x39, 0xc6, 0x29 } };

typedef struct _TRUSTAGENT_RULE_SET {
    UINT32 ProxyIpv4;
    UINT16 ProxyPort;
    UINT32 ProxyPid;
    UINT16 Flags;
    UINT32 RuleCount;
    PTRUSTAGENT_WFP_RULE Rules;
} TRUSTAGENT_RULE_SET, *PTRUSTAGENT_RULE_SET;

typedef struct _TRUSTAGENT_DEVICE_CONTEXT {
    WDFSPINLOCK Lock;
    TRUSTAGENT_RULE_SET Rules;
    HANDLE EngineHandle;
    HANDLE RedirectHandle;
    UINT32 CalloutIdV4;
    UINT64 FilterIdV4;
} TRUSTAGENT_DEVICE_CONTEXT, *PTRUSTAGENT_DEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(TRUSTAGENT_DEVICE_CONTEXT, TrustAgentGetDeviceContext);

static VOID TrustAgentEvtDeviceContextCleanup(_In_ WDFOBJECT Object);
static NTSTATUS TrustAgentRegisterWfp(_In_ WDFDEVICE Device, _Inout_ PTRUSTAGENT_DEVICE_CONTEXT Context);
static VOID TrustAgentUnregisterWfp(_Inout_ PTRUSTAGENT_DEVICE_CONTEXT Context);

static VOID TrustAgentFreeRules(_Inout_ PTRUSTAGENT_RULE_SET RuleSet)
{
    if (RuleSet->Rules != NULL) {
        ExFreePoolWithTag(RuleSet->Rules, 'fWaT');
        RuleSet->Rules = NULL;
    }
    RuleSet->RuleCount = 0;
    RuleSet->ProxyIpv4 = 0;
    RuleSet->ProxyPort = 0;
    RuleSet->ProxyPid = 0;
    RuleSet->Flags = 0;
}

static BOOLEAN TrustAgentRuleMatches(
    _In_ const TRUSTAGENT_WFP_RULE* Rule,
    _In_ UINT32 RemoteIpv4,
    _In_ UINT16 RemotePort,
    _In_ UINT8 Protocol)
{
    if (Rule->Protocol != Protocol) {
        return FALSE;
    }
    if (Rule->SyntheticIpv4 != RemoteIpv4) {
        return FALSE;
    }
    return Rule->Port == 0 || Rule->Port == RemotePort;
}

static BOOLEAN TrustAgentFindMatchingRule(
    _In_ PTRUSTAGENT_DEVICE_CONTEXT Context,
    _In_ UINT32 RemoteIpv4,
    _In_ UINT16 RemotePort,
    _In_ UINT8 Protocol,
    _Out_ TRUSTAGENT_WFP_RULE* MatchedRule,
    _Out_ UINT32* ProxyIpv4,
    _Out_ UINT16* ProxyPort,
    _Out_ UINT32* ProxyPid,
    _Out_ UINT16* Flags)
{
    BOOLEAN found = FALSE;
    UINT32 index;

    WdfSpinLockAcquire(Context->Lock);
    for (index = 0; index < Context->Rules.RuleCount; index++) {
        if (TrustAgentRuleMatches(&Context->Rules.Rules[index], RemoteIpv4, RemotePort, Protocol)) {
            *MatchedRule = Context->Rules.Rules[index];
            *ProxyIpv4 = Context->Rules.ProxyIpv4;
            *ProxyPort = Context->Rules.ProxyPort;
            *ProxyPid = Context->Rules.ProxyPid;
            *Flags = Context->Rules.Flags;
            found = TRUE;
            break;
        }
    }
    WdfSpinLockRelease(Context->Lock);
    return found;
}

static VOID TrustAgentSetPermit(_Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    ClassifyOut->actionType = FWP_ACTION_PERMIT;
}

static VOID TrustAgentSetBlock(_Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    ClassifyOut->actionType = FWP_ACTION_BLOCK;
    ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static BOOLEAN TrustAgentWasAlreadyRedirected(
    _In_ PTRUSTAGENT_DEVICE_CONTEXT Context,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* MetaValues)
{
    FWPS_CONNECTION_REDIRECT_STATE redirectState;
    void* redirectContext = NULL;

    if (Context->RedirectHandle == NULL ||
        MetaValues == NULL ||
        !FWPS_IS_METADATA_FIELD_PRESENT(MetaValues, FWPS_METADATA_FIELD_REDIRECT_RECORD_HANDLE)) {
        return FALSE;
    }

    redirectState = FwpsQueryConnectionRedirectState0(
        MetaValues->redirectRecords,
        Context->RedirectHandle,
        &redirectContext);

    return redirectState == FWPS_CONNECTION_REDIRECTED_BY_SELF ||
           redirectState == FWPS_CONNECTION_PREVIOUSLY_REDIRECTED_BY_SELF;
}

static NTSTATUS TrustAgentRedirectConnectV4(
    _In_ const void* ClassifyContext,
    _In_ const FWPS_FILTER1* Filter,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut,
    _In_ UINT32 OriginalIpv4,
    _In_ UINT16 OriginalPort,
    _In_ UINT8 Protocol,
    _In_ UINT32 OriginalProcessId,
    _In_ UINT32 ProxyIpv4,
    _In_ UINT16 ProxyPort,
    _In_ UINT32 ProxyPid,
    _In_ HANDLE RedirectHandle)
{
    NTSTATUS status;
    UINT64 classifyHandle = 0;
    FWPS_CONNECT_REQUEST0* connectRequest = NULL;
    SOCKADDR_IN* remoteAddress;
    PTRUSTAGENT_WFP_ORIGINAL_TARGET redirectContext = NULL;

    redirectContext = (PTRUSTAGENT_WFP_ORIGINAL_TARGET)ExAllocatePoolWithTag(
        NonPagedPoolNx,
        sizeof(TRUSTAGENT_WFP_ORIGINAL_TARGET),
        'cWaT');
    if (redirectContext == NULL) {
        FwpsReleaseClassifyHandle0(classifyHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(redirectContext, sizeof(*redirectContext));
    redirectContext->Magic = TRUSTAGENT_WFP_MAGIC;
    redirectContext->Version = TRUSTAGENT_WFP_VERSION;
    redirectContext->OriginalIpv4 = OriginalIpv4;
    redirectContext->OriginalPort = OriginalPort;
    redirectContext->Protocol = Protocol;
    redirectContext->OriginalProcessId = OriginalProcessId;

    status = FwpsAcquireClassifyHandle0((void*)ClassifyContext, 0, &classifyHandle);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(redirectContext, 'cWaT');
        return status;
    }

    status = FwpsAcquireWritableLayerDataPointer0(
        classifyHandle,
        Filter->filterId,
        0,
        (PVOID*)&connectRequest,
        ClassifyOut);
    if (!NT_SUCCESS(status)) {
        FwpsReleaseClassifyHandle0(classifyHandle);
        ExFreePoolWithTag(redirectContext, 'cWaT');
        return status;
    }

    RtlZeroMemory(&connectRequest->remoteAddressAndPort, sizeof(connectRequest->remoteAddressAndPort));
    remoteAddress = (SOCKADDR_IN*)&connectRequest->remoteAddressAndPort;
    remoteAddress->sin_family = AF_INET;
    remoteAddress->sin_port = RtlUshortByteSwap(ProxyPort);
    remoteAddress->sin_addr.S_un.S_addr = RtlUlongByteSwap(ProxyIpv4);

    connectRequest->localRedirectTargetPID = ProxyPid;
    connectRequest->localRedirectHandle = RedirectHandle;
    connectRequest->localRedirectContext = redirectContext;
    connectRequest->localRedirectContextSize = sizeof(*redirectContext);

    FwpsApplyModifiedLayerData0(classifyHandle, connectRequest, 0);
    FwpsReleaseClassifyHandle0(classifyHandle);
    return STATUS_SUCCESS;
}

static VOID NTAPI TrustAgentClassifyConnectRedirectV4(
    _In_ const FWPS_INCOMING_VALUES0* InFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* InMetaValues,
    _Inout_opt_ void* LayerData,
    _In_opt_ const void* ClassifyContext,
    _In_ const FWPS_FILTER1* Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* ClassifyOut)
{
    PTRUSTAGENT_DEVICE_CONTEXT context;
    TRUSTAGENT_WFP_RULE matchedRule;
    UINT32 remoteIpv4;
    UINT16 remotePort;
    UINT8 protocol;
    UINT32 proxyIpv4;
    UINT16 proxyPort;
    UINT32 proxyPid;
    UINT32 originalProcessId;
    UINT16 flags;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(FlowContext);

    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0 ||
        InFixedValues == NULL ||
        InFixedValues->valueCount <= FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT ||
        Filter == NULL) {
        return;
    }

    context = (PTRUSTAGENT_DEVICE_CONTEXT)(UINT_PTR)Filter->context;
    if (context == NULL || context->RedirectHandle == NULL) {
        TrustAgentSetPermit(ClassifyOut);
        return;
    }

    protocol = InFixedValues
        ->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_PROTOCOL]
        .value.uint8;
    remoteIpv4 = InFixedValues
        ->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS]
        .value.uint32;
    remotePort = InFixedValues
        ->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT]
        .value.uint16;
    originalProcessId = 0;
    if (InMetaValues != NULL &&
        FWPS_IS_METADATA_FIELD_PRESENT(InMetaValues, FWPS_METADATA_FIELD_PROCESS_ID)) {
        originalProcessId = (UINT32)InMetaValues->processId;
    }

    if (protocol != TRUSTAGENT_TCP_PROTOCOL ||
        remoteIpv4 == TRUSTAGENT_IPV4_LOOPBACK ||
        TrustAgentWasAlreadyRedirected(context, InMetaValues)) {
        TrustAgentSetPermit(ClassifyOut);
        return;
    }

    if (!TrustAgentFindMatchingRule(
            context,
            remoteIpv4,
            remotePort,
            protocol,
            &matchedRule,
            &proxyIpv4,
            &proxyPort,
            &proxyPid,
            &flags)) {
        TrustAgentSetPermit(ClassifyOut);
        return;
    }

    status = TrustAgentRedirectConnectV4(
        ClassifyContext,
        Filter,
        ClassifyOut,
        matchedRule.SyntheticIpv4,
        remotePort,
        protocol,
        originalProcessId,
        proxyIpv4,
        proxyPort,
        proxyPid,
        context->RedirectHandle);

    if (NT_SUCCESS(status)) {
        TrustAgentSetPermit(ClassifyOut);
        return;
    }

    if ((flags & TRUSTAGENT_WFP_FLAG_FAIL_CLOSED) != 0) {
        TrustAgentSetBlock(ClassifyOut);
        return;
    }

    TrustAgentSetPermit(ClassifyOut);
}

static NTSTATUS NTAPI TrustAgentNotifyFn(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID* FilterKey,
    _Inout_ FWPS_FILTER1* Filter)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

static NTSTATUS TrustAgentStoreRules(
    _In_ PTRUSTAGENT_DEVICE_CONTEXT Context,
    _In_reads_bytes_(InputLength) PVOID InputBuffer,
    _In_ size_t InputLength)
{
    PTRUSTAGENT_WFP_APPLY_RULES request = (PTRUSTAGENT_WFP_APPLY_RULES)InputBuffer;
    size_t expectedLength;
    size_t rulesLength;
    PTRUSTAGENT_WFP_RULE rulesCopy;
    TRUSTAGENT_RULE_SET oldRules;

    if (InputLength < FIELD_OFFSET(TRUSTAGENT_WFP_APPLY_RULES, Rules)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (request->Magic != TRUSTAGENT_WFP_MAGIC || request->Version != TRUSTAGENT_WFP_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->ProxyIpv4 == 0 || request->ProxyPort == 0 || request->ProxyPid == 0) {
        return STATUS_INVALID_PARAMETER;
    }
    if (request->RuleCount > 4096) {
        return STATUS_INVALID_PARAMETER;
    }

    rulesLength = request->RuleCount * sizeof(TRUSTAGENT_WFP_RULE);
    expectedLength = FIELD_OFFSET(TRUSTAGENT_WFP_APPLY_RULES, Rules) + rulesLength;
    if (InputLength < expectedLength) {
        return STATUS_BUFFER_TOO_SMALL;
    }

    rulesCopy = NULL;
    if (rulesLength > 0) {
        rulesCopy = (PTRUSTAGENT_WFP_RULE)ExAllocatePoolWithTag(NonPagedPoolNx, rulesLength, 'fWaT');
        if (rulesCopy == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        RtlCopyMemory(rulesCopy, request->Rules, rulesLength);
    }

    RtlZeroMemory(&oldRules, sizeof(oldRules));
    WdfSpinLockAcquire(Context->Lock);
    oldRules = Context->Rules;
    Context->Rules.ProxyIpv4 = request->ProxyIpv4;
    Context->Rules.ProxyPort = request->ProxyPort;
    Context->Rules.ProxyPid = request->ProxyPid;
    Context->Rules.Flags = request->Flags;
    Context->Rules.RuleCount = request->RuleCount;
    Context->Rules.Rules = rulesCopy;
    WdfSpinLockRelease(Context->Lock);

    TrustAgentFreeRules(&oldRules);
    return STATUS_SUCCESS;
}

static NTSTATUS TrustAgentAddProvider(_In_ HANDLE EngineHandle)
{
    NTSTATUS status;
    FWPM_PROVIDER0 provider;

    RtlZeroMemory(&provider, sizeof(provider));
    provider.providerKey = TRUSTAGENT_WFP_PROVIDER_KEY;
    provider.displayData.name = (wchar_t*)L"TrustAgent WFP Provider";
    provider.displayData.description = (wchar_t*)L"TrustAgent traffic redirection provider";

    status = FwpmProviderAdd0(EngineHandle, &provider, NULL);
    if (status == STATUS_FWP_ALREADY_EXISTS) {
        return STATUS_SUCCESS;
    }
    return status;
}

static NTSTATUS TrustAgentAddSublayer(_In_ HANDLE EngineHandle)
{
    NTSTATUS status;
    FWPM_SUBLAYER0 sublayer;

    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = TRUSTAGENT_WFP_SUBLAYER_KEY;
    sublayer.displayData.name = (wchar_t*)L"TrustAgent";
    sublayer.displayData.description = (wchar_t*)L"TrustAgent protected resource redirection";
    sublayer.providerKey = (GUID*)&TRUSTAGENT_WFP_PROVIDER_KEY;
    sublayer.weight = 0x8000;

    status = FwpmSubLayerAdd0(EngineHandle, &sublayer, NULL);
    if (status == STATUS_FWP_ALREADY_EXISTS) {
        return STATUS_SUCCESS;
    }
    return status;
}

static NTSTATUS TrustAgentAddCallout(
    _In_ HANDLE EngineHandle,
    _In_ UINT32 CalloutId)
{
    NTSTATUS status;
    FWPM_CALLOUT0 callout;

    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = TRUSTAGENT_WFP_CALLOUT_CONNECT_V4_KEY;
    callout.displayData.name = (wchar_t*)L"TrustAgent ALE connect redirect v4";
    callout.displayData.description = (wchar_t*)L"Redirects TrustAgent synthetic IPv4 connections";
    callout.providerKey = (GUID*)&TRUSTAGENT_WFP_PROVIDER_KEY;
    callout.applicableLayer = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    callout.calloutId = CalloutId;

    status = FwpmCalloutAdd0(EngineHandle, &callout, NULL, NULL);
    if (status == STATUS_FWP_ALREADY_EXISTS) {
        return STATUS_SUCCESS;
    }
    return status;
}

static NTSTATUS TrustAgentAddConnectFilter(
    _In_ HANDLE EngineHandle,
    _In_ PTRUSTAGENT_DEVICE_CONTEXT Context)
{
    FWPM_FILTER0 filter;
    FWPM_FILTER_CONDITION0 conditions[2];
    FWP_V4_ADDR_AND_MASK syntheticRange;

    RtlZeroMemory(&filter, sizeof(filter));
    RtlZeroMemory(conditions, sizeof(conditions));
    RtlZeroMemory(&syntheticRange, sizeof(syntheticRange));

    syntheticRange.addr = TRUSTAGENT_CGNAT_BASE;
    syntheticRange.mask = TRUSTAGENT_CGNAT_MASK;

    conditions[0].fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_V4_ADDR_MASK;
    conditions[0].conditionValue.v4AddrMask = &syntheticRange;

    conditions[1].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
    conditions[1].matchType = FWP_MATCH_EQUAL;
    conditions[1].conditionValue.type = FWP_UINT8;
    conditions[1].conditionValue.uint8 = TRUSTAGENT_TCP_PROTOCOL;

    filter.filterKey = TRUSTAGENT_WFP_FILTER_CONNECT_V4_KEY;
    filter.displayData.name = (wchar_t*)L"TrustAgent protected IPv4 redirect";
    filter.displayData.description = (wchar_t*)L"Routes 100.64.0.0/10 TCP connections through TrustAgent";
    filter.providerKey = (GUID*)&TRUSTAGENT_WFP_PROVIDER_KEY;
    filter.layerKey = FWPM_LAYER_ALE_CONNECT_REDIRECT_V4;
    filter.subLayerKey = TRUSTAGENT_WFP_SUBLAYER_KEY;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = 0x0F;
    filter.numFilterConditions = RTL_NUMBER_OF(conditions);
    filter.filterCondition = conditions;
    filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
    filter.action.calloutKey = TRUSTAGENT_WFP_CALLOUT_CONNECT_V4_KEY;
    filter.rawContext = (UINT64)(UINT_PTR)Context;

    return FwpmFilterAdd0(EngineHandle, &filter, NULL, &Context->FilterIdV4);
}

static NTSTATUS TrustAgentRegisterWfp(_In_ WDFDEVICE Device, _Inout_ PTRUSTAGENT_DEVICE_CONTEXT Context)
{
    NTSTATUS status;
    FWPS_CALLOUT1 runtimeCallout;
    FWPM_SESSION0 session;

    RtlZeroMemory(&session, sizeof(session));
    session.displayData.name = (wchar_t*)L"TrustAgent WFP Session";
    session.flags = FWPM_SESSION_FLAG_DYNAMIC;
    session.kernelMode = TRUE;

    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, &Context->EngineHandle);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    FwpmFilterDeleteByKey0(Context->EngineHandle, &TRUSTAGENT_WFP_FILTER_CONNECT_V4_KEY);
    FwpmCalloutDeleteByKey0(Context->EngineHandle, &TRUSTAGENT_WFP_CALLOUT_CONNECT_V4_KEY);
    FwpmSubLayerDeleteByKey0(Context->EngineHandle, &TRUSTAGENT_WFP_SUBLAYER_KEY);
    FwpmProviderDeleteByKey0(Context->EngineHandle, &TRUSTAGENT_WFP_PROVIDER_KEY);

    status = FwpsRedirectHandleCreate0(&TRUSTAGENT_WFP_PROVIDER_KEY, 0, &Context->RedirectHandle);
    if (!NT_SUCCESS(status)) {
        TrustAgentUnregisterWfp(Context);
        return status;
    }

    RtlZeroMemory(&runtimeCallout, sizeof(runtimeCallout));
    runtimeCallout.calloutKey = TRUSTAGENT_WFP_CALLOUT_CONNECT_V4_KEY;
    runtimeCallout.classifyFn = TrustAgentClassifyConnectRedirectV4;
    runtimeCallout.notifyFn = TrustAgentNotifyFn;

    status = FwpsCalloutRegister1(
        WdfDeviceWdmGetDeviceObject(Device),
        &runtimeCallout,
        &Context->CalloutIdV4);
    if (!NT_SUCCESS(status)) {
        TrustAgentUnregisterWfp(Context);
        return status;
    }

    status = TrustAgentAddProvider(Context->EngineHandle);
    if (NT_SUCCESS(status)) {
        status = TrustAgentAddSublayer(Context->EngineHandle);
    }
    if (NT_SUCCESS(status)) {
        status = TrustAgentAddCallout(Context->EngineHandle, Context->CalloutIdV4);
    }
    if (NT_SUCCESS(status)) {
        status = TrustAgentAddConnectFilter(Context->EngineHandle, Context);
    }
    if (!NT_SUCCESS(status)) {
        TrustAgentUnregisterWfp(Context);
        return status;
    }

    return STATUS_SUCCESS;
}

static VOID TrustAgentUnregisterWfp(_Inout_ PTRUSTAGENT_DEVICE_CONTEXT Context)
{
    if (Context->EngineHandle != NULL) {
        if (Context->FilterIdV4 != 0) {
            FwpmFilterDeleteById0(Context->EngineHandle, Context->FilterIdV4);
            Context->FilterIdV4 = 0;
        } else {
            FwpmFilterDeleteByKey0(Context->EngineHandle, &TRUSTAGENT_WFP_FILTER_CONNECT_V4_KEY);
        }

        FwpmCalloutDeleteByKey0(Context->EngineHandle, &TRUSTAGENT_WFP_CALLOUT_CONNECT_V4_KEY);
        FwpmSubLayerDeleteByKey0(Context->EngineHandle, &TRUSTAGENT_WFP_SUBLAYER_KEY);
        FwpmProviderDeleteByKey0(Context->EngineHandle, &TRUSTAGENT_WFP_PROVIDER_KEY);
    }

    if (Context->CalloutIdV4 != 0) {
        FwpsCalloutUnregisterById0(Context->CalloutIdV4);
        Context->CalloutIdV4 = 0;
    }

    if (Context->RedirectHandle != NULL) {
        FwpsRedirectHandleDestroy0(Context->RedirectHandle);
        Context->RedirectHandle = NULL;
    }

    if (Context->EngineHandle != NULL) {
        FwpmEngineClose0(Context->EngineHandle);
        Context->EngineHandle = NULL;
    }
}

static VOID TrustAgentEvtDeviceContextCleanup(_In_ WDFOBJECT Object)
{
    PTRUSTAGENT_DEVICE_CONTEXT context = TrustAgentGetDeviceContext((WDFDEVICE)Object);
    TRUSTAGENT_RULE_SET oldRules;

    TrustAgentUnregisterWfp(context);

    RtlZeroMemory(&oldRules, sizeof(oldRules));
    WdfSpinLockAcquire(context->Lock);
    oldRules = context->Rules;
    RtlZeroMemory(&context->Rules, sizeof(context->Rules));
    WdfSpinLockRelease(context->Lock);
    TrustAgentFreeRules(&oldRules);
}

static NTSTATUS TrustAgentQueryOriginalTarget(
    _In_ PTRUSTAGENT_DEVICE_CONTEXT Context,
    _In_reads_bytes_(InputLength) PVOID InputBuffer,
    _In_ size_t InputLength,
    _Out_writes_bytes_(OutputLength) PVOID OutputBuffer,
    _In_ size_t OutputLength,
    _Out_ size_t* BytesReturned)
{
    PTRUSTAGENT_WFP_CONNECTION_QUERY query = (PTRUSTAGENT_WFP_CONNECTION_QUERY)InputBuffer;
    PTRUSTAGENT_WFP_ORIGINAL_TARGET response = (PTRUSTAGENT_WFP_ORIGINAL_TARGET)OutputBuffer;

    UNREFERENCED_PARAMETER(Context);

    if (InputLength < sizeof(TRUSTAGENT_WFP_CONNECTION_QUERY)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (OutputLength < sizeof(TRUSTAGENT_WFP_ORIGINAL_TARGET)) {
        return STATUS_BUFFER_TOO_SMALL;
    }
    if (query->Magic != TRUSTAGENT_WFP_MAGIC || query->Version != TRUSTAGENT_WFP_VERSION) {
        return STATUS_INVALID_PARAMETER;
    }

    /*
     * Production step:
     * The classify path must persist the original destination for each redirected flow.
     * This IOCTL looks up that flow using the accepted proxy connection tuple and returns
     * the original synthetic destination to the Go proxy.
     */
    RtlZeroMemory(response, sizeof(*response));
    response->Magic = TRUSTAGENT_WFP_MAGIC;
    response->Version = TRUSTAGENT_WFP_VERSION;
    *BytesReturned = sizeof(*response);
    return STATUS_NOT_FOUND;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    WDF_DRIVER_CONFIG config;
    WDF_DRIVER_CONFIG_INIT(&config, TrustAgentEvtDeviceAdd);
    return WdfDriverCreate(DriverObject, RegistryPath, WDF_NO_OBJECT_ATTRIBUTES, &config, WDF_NO_HANDLE);
}

NTSTATUS TrustAgentEvtDeviceAdd(_In_ WDFDRIVER Driver, _Inout_ PWDFDEVICE_INIT DeviceInit)
{
    NTSTATUS status;
    WDFDEVICE device;
    WDF_OBJECT_ATTRIBUTES attributes;
    WDF_IO_QUEUE_CONFIG queueConfig;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLink;
    PTRUSTAGENT_DEVICE_CONTEXT context;

    UNREFERENCED_PARAMETER(Driver);

    RtlInitUnicodeString(&deviceName, TRUSTAGENT_WFP_DEVICE_NAME);
    status = WdfDeviceInitAssignName(DeviceInit, &deviceName);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attributes, TRUSTAGENT_DEVICE_CONTEXT);
    attributes.EvtCleanupCallback = TrustAgentEvtDeviceContextCleanup;
    status = WdfDeviceCreate(&DeviceInit, &attributes, &device);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    context = TrustAgentGetDeviceContext(device);
    RtlZeroMemory(context, sizeof(*context));
    status = WdfSpinLockCreate(WDF_NO_OBJECT_ATTRIBUTES, &context->Lock);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = TrustAgentRegisterWfp(device, context);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&symbolicLink, TRUSTAGENT_WFP_SYMBOLIC_LINK);
    status = WdfDeviceCreateSymbolicLink(device, &symbolicLink);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoDeviceControl = TrustAgentEvtIoDeviceControl;
    return WdfIoQueueCreate(device, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE);
}

VOID TrustAgentEvtIoDeviceControl(
    _In_ WDFQUEUE Queue,
    _In_ WDFREQUEST Request,
    _In_ size_t OutputBufferLength,
    _In_ size_t InputBufferLength,
    _In_ ULONG IoControlCode)
{
    NTSTATUS status;
    WDFDEVICE device = WdfIoQueueGetDevice(Queue);
    PTRUSTAGENT_DEVICE_CONTEXT context = TrustAgentGetDeviceContext(device);
    PVOID inputBuffer = NULL;
    PVOID outputBuffer = NULL;
    size_t bytesReturned = 0;

    switch (IoControlCode) {
    case IOCTL_TRUSTAGENT_WFP_APPLY_RULES:
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inputBuffer, NULL);
        if (NT_SUCCESS(status)) {
            status = TrustAgentStoreRules(context, inputBuffer, InputBufferLength);
        }
        break;

    case IOCTL_TRUSTAGENT_WFP_CLEAR_RULES:
    {
        TRUSTAGENT_RULE_SET oldRules;
        RtlZeroMemory(&oldRules, sizeof(oldRules));
        WdfSpinLockAcquire(context->Lock);
        oldRules = context->Rules;
        RtlZeroMemory(&context->Rules, sizeof(context->Rules));
        WdfSpinLockRelease(context->Lock);
        TrustAgentFreeRules(&oldRules);
        status = STATUS_SUCCESS;
        break;
    }

    case IOCTL_TRUSTAGENT_WFP_QUERY_ORIGINAL_TARGET:
        status = WdfRequestRetrieveInputBuffer(Request, InputBufferLength, &inputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        status = WdfRequestRetrieveOutputBuffer(Request, OutputBufferLength, &outputBuffer, NULL);
        if (!NT_SUCCESS(status)) {
            break;
        }
        status = TrustAgentQueryOriginalTarget(
            context,
            inputBuffer,
            InputBufferLength,
            outputBuffer,
            OutputBufferLength,
            &bytesReturned);
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    WdfRequestCompleteWithInformation(Request, status, bytesReturned);
}
