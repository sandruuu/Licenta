import { AlertCircle, CheckCircle2, ChevronDown, Edit, Key, Loader2, Plus, Shield, Star, Trash2, Users, X } from 'lucide-react';
import StatusBadge from './StatusBadge';

const idpLabelClass = 'block text-[10px] font-semibold text-text-secondary uppercase tracking-[0.2px] mb-1.5';
const idpInputClass = 'w-full h-9 px-3 bg-surface border border-border rounded text-[12px] text-text-primary focus:outline-none focus:border-accent focus:ring-[3px] focus:ring-accent-muted transition-colors';
const idpMonoInputClass = `${idpInputClass} font-mono`;

export default function IdentityProviderManagerModal({
  tenantName, idps, idpLoading, idpError, idpModal, setIdpModal, idpForm, setIdpForm,
  idpSaving, testResult, testing, idpAdvancedOpen, setIdpAdvancedOpen,
  onClose, onCreate, onEdit, onDelete, onSetDefault, onTestConnection, onSave,
  addGroupRule, updateGroupRule, removeGroupRule, federatedCallbackURL,
}) {
  return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm p-4">
          <div className="bg-surface-card rounded-md border border-border shadow-2xl w-[min(920px,calc(100vw-32px))] h-[min(620px,calc(100vh-48px))] overflow-hidden flex flex-col">
            <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-surface-card flex-shrink-0">
              <div>
                <h2 className="text-base font-semibold text-text-primary">
                  Identity Providers — {tenantName}
                </h2>
                <p className="text-[11px] text-text-muted mt-0.5">OIDC client registrations. HRD uses the tenant primary domain and aliases.</p>
              </div>
              <button onClick={onClose} className="p-1 text-text-muted hover:text-text-primary rounded-md">
                <X size={20} />
              </button>
            </div>

            <div className="px-6 py-4 border-b border-border bg-surface-secondary flex-shrink-0">
              <div className="flex items-center justify-between gap-4">
                <span className="text-xs font-medium text-text-secondary">
                  {idps.length} provider{idps.length === 1 ? '' : 's'} configured
                </span>
                <button onClick={onCreate}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold bg-accent text-white rounded-md hover:bg-accent-hover transition-colors">
                  <Plus size={14} /> Add Provider
                </button>
              </div>
            </div>

            <div className="p-6 overflow-y-auto flex-1">
              {idpError && (
                <div className="bg-danger-muted border border-danger rounded-md p-3 text-sm text-danger mb-4">{idpError}</div>
              )}

              {idpLoading ? (
                <div className="text-center py-10 text-text-muted text-sm">Loading...</div>
              ) : idps.length === 0 ? (
                <div className="text-center py-12 border border-dashed border-border rounded-md">
                  <Shield size={32} className="mx-auto mb-2 opacity-40" />
                  <p className="text-sm font-medium text-text-primary">No identity providers</p>
                  <p className="text-xs text-text-muted mt-1">Add the first OIDC registration for this organization.</p>
                </div>
              ) : (
                <div className="border border-border rounded-md overflow-hidden">
                  <table className="w-full table-fixed">
                    <thead className="bg-surface-secondary">
                      <tr>
                        <th className="w-[28%] text-left px-4 py-2.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.6px]">Provider</th>
                        <th className="w-[22%] text-left px-4 py-2.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.6px]">Client ID</th>
                        <th className="w-[36%] text-left px-4 py-2.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.6px]">Issuer</th>
                        <th className="w-[14%] text-right px-4 py-2.5 text-[10px] font-semibold text-text-muted uppercase tracking-[0.6px]">Actions</th>
                    </tr>
                  </thead>
                    <tbody className="divide-y divide-border bg-surface-card">
                    {idps.map((idp) => (
                      <tr key={idp.id} className="hover:bg-surface-hover">
                          <td className="px-4 py-3 align-top">
                            <div className="flex items-start gap-2 min-w-0">
                              <Key size={14} className="text-accent flex-shrink-0 mt-0.5" />
                              <div className="min-w-0">
                                <div className="flex items-center gap-1.5 min-w-0">
                                  <p className="text-xs font-semibold text-text-primary truncate">{idp.name}</p>
                                {idp.is_default ? (
                                    <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded text-[9px] font-semibold bg-accent-muted text-accent flex-shrink-0">
                                    <Star size={9} fill="currentColor" /> Default
                                  </span>
                                ) : null}
                              </div>
                                <div className="mt-1"><StatusBadge enabled={idp.enabled} /></div>
                            </div>
                          </div>
                        </td>
                          <td className="px-4 py-3 align-top">
                            <span className="block text-[11px] text-text-secondary font-mono truncate" title={idp.client_id || ''}>{idp.client_id || '-'}</span>
                        </td>
                          <td className="px-4 py-3 align-top">
                            <span className="block text-[11px] text-text-secondary font-mono break-all line-clamp-2" title={idp.issuer || ''}>{idp.issuer || '-'}</span>
                        </td>
                          <td className="px-4 py-3 align-top">
                            <div className="flex justify-end gap-1">
                            {!idp.is_default && idp.enabled !== false ? (
                              <button onClick={() => onSetDefault(idp)}
                                className="p-1 text-text-secondary hover:bg-accent-muted hover:text-accent rounded transition-colors" title="Set as default">
                                <Star size={14} />
                              </button>
                            ) : null}
                            <button onClick={() => onEdit(idp)}
                              className="p-1 text-text-secondary hover:bg-surface-hover rounded transition-colors" title="Edit">
                              <Edit size={14} />
                            </button>
                            <button onClick={() => onDelete(idp.id)}
                              className="p-1 text-danger hover:bg-danger-muted rounded transition-colors" title="Delete">
                              <Trash2 size={14} />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                </div>
              )}
            </div>
          </div>

          {/* ─── IdP Create/Edit Modal (nested) ─── */}
          {idpModal ? (
            <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/50 backdrop-blur-sm p-4">
              <div className="bg-surface-card rounded-md border border-border shadow-2xl w-[min(720px,calc(100vw-32px))] h-[min(700px,calc(100vh-48px))] overflow-hidden flex flex-col">
                <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-surface-card flex-shrink-0">
                  <h3 className="text-sm font-semibold text-text-primary">
                    {idpModal === 'create' ? 'Add OIDC Client Registration' : 'Edit OIDC Client Registration'}
                  </h3>
                  <button onClick={() => setIdpModal(null)} className="p-1 text-text-muted hover:text-text-primary rounded-md">
                    <X size={18} />
                  </button>
                </div>

                <div className="p-6 space-y-5 overflow-y-auto flex-1">
                  {idpError && (
                    <div className="bg-danger-muted border border-danger rounded-md p-3 text-xs text-danger">{idpError}</div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className={idpLabelClass}>Provider name *</label>
                      <input type="text" value={idpForm.name || ''} onChange={(e) => setIdpForm({ ...idpForm, name: e.target.value })}
                        className={idpInputClass}
                        placeholder="Keycloak Lab" />
                    </div>
                    <div>
                      <label className={idpLabelClass}>OIDC client ID *</label>
                      <input type="text" value={idpForm.client_id || ''} onChange={(e) => setIdpForm({ ...idpForm, client_id: e.target.value })}
                        className={idpMonoInputClass}
                        placeholder="ztna-pdp" />
                    </div>
                    <div className="md:col-span-2">
                      <label className={idpLabelClass}>Issuer URL *</label>
                      <input type="text" value={idpForm.issuer || ''} onChange={(e) => setIdpForm({ ...idpForm, issuer: e.target.value })}
                        className={idpMonoInputClass}
                        placeholder="http://keycloak.ztna.local:8080/realms/ztna-lab" />
                    </div>
                    <div>
                      <label className={idpLabelClass}>
                        OIDC client secret
                        {idpModal === 'edit' && idpForm.has_client_secret ? (
                          <span className="ml-2 px-1.5 py-0.5 rounded bg-success-muted text-success text-[9px] normal-case tracking-normal">saved</span>
                        ) : null}
                      </label>
                      <input type="password" value={idpForm.client_secret || ''} onChange={(e) => setIdpForm({ ...idpForm, client_secret: e.target.value })}
                        className={idpInputClass}
                        placeholder={idpModal === 'edit' ? 'Leave blank to keep saved secret' : 'Required for confidential clients'} />
                    </div>
                    <div>
                      <label className={idpLabelClass}>Scopes</label>
                      <input type="text" value={idpForm.scopes || ''} onChange={(e) => setIdpForm({ ...idpForm, scopes: e.target.value })}
                        className={idpMonoInputClass} />
                    </div>
                    <div>
                      <label className={idpLabelClass}>Callback URL</label>
                      <input type="text" value={federatedCallbackURL} readOnly
                        className={`${idpMonoInputClass} text-text-muted bg-surface-secondary`} />
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-x-5 gap-y-2 border-t border-border pt-4">
                    <label className="flex items-center gap-2 cursor-pointer text-[12px] text-text-secondary">
                      <input type="checkbox" checked={idpForm.enabled !== false}
                        onChange={(e) => setIdpForm({ ...idpForm, enabled: e.target.checked, is_default: e.target.checked ? idpForm.is_default : false })}
                        className="rounded border-border text-accent" /> Enabled
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer text-[12px] text-text-secondary">
                      <input type="checkbox" checked={idpForm.is_default === true}
                        onChange={(e) => setIdpForm({ ...idpForm, is_default: e.target.checked })}
                        disabled={idpForm.enabled === false || (idpModal === 'edit' && idpForm.is_default === true) || (idpModal === 'create' && idps.length === 0)}
                        className="rounded border-border text-accent disabled:opacity-50" /> Default for tenant
                    </label>
                    <label className="flex items-center gap-2 cursor-pointer text-[12px] text-text-secondary">
                      <input type="checkbox" checked={idpForm.auto_discovery !== false}
                        onChange={(e) => setIdpForm({ ...idpForm, auto_discovery: e.target.checked })}
                        className="rounded border-border text-accent" /> Auto-discovery
                    </label>
                  </div>

                  <div className="border-t border-border pt-4">
                    <button type="button" onClick={() => setIdpAdvancedOpen((open) => !open)}
                      className="w-full flex items-center justify-between text-left">
                      <span className="inline-flex items-center gap-2 text-xs font-semibold text-text-primary">
                        <ChevronDown size={14} className={`text-text-muted transition-transform ${idpAdvancedOpen ? '' : '-rotate-90'}`} />
                        Advanced mapping
                      </span>
                      <span className="text-[11px] text-text-muted">
                        {(idpForm.group_role_mapping || []).length} role rule{(idpForm.group_role_mapping || []).length === 1 ? '' : 's'}
                      </span>
                    </button>

                    {idpAdvancedOpen ? (
                      <div className="mt-4 space-y-5">
                        <div>
                          <h4 className="text-xs font-semibold text-text-primary mb-3 flex items-center gap-1.5">
                            <Key size={14} className="text-accent" /> Claims
                          </h4>
                          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                            <div>
                              <label className={idpLabelClass}>Username claim</label>
                              <input type="text" value={idpForm.claim_username || ''}
                                onChange={(e) => setIdpForm({ ...idpForm, claim_username: e.target.value })}
                                className={idpMonoInputClass} />
                            </div>
                            <div>
                              <label className={idpLabelClass}>Email claim</label>
                              <input type="text" value={idpForm.claim_email || ''}
                                onChange={(e) => setIdpForm({ ...idpForm, claim_email: e.target.value })}
                                className={idpMonoInputClass} />
                            </div>
                            <div>
                              <label className={idpLabelClass}>Groups claim</label>
                              <input type="text" value={idpForm.claim_groups || ''}
                                onChange={(e) => setIdpForm({ ...idpForm, claim_groups: e.target.value })}
                                className={idpMonoInputClass} />
                            </div>
                          </div>
                        </div>

                        <div>
                          <div className="flex items-center justify-between mb-3">
                            <h4 className="text-xs font-semibold text-text-primary flex items-center gap-1.5">
                              <Users size={14} className="text-accent" /> Group roles
                            </h4>
                            <button onClick={addGroupRule}
                              className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[11px] font-semibold border border-border rounded text-text-secondary hover:bg-surface-hover transition-colors">
                              <Plus size={10} /> Add
                            </button>
                          </div>

                          {(idpForm.group_role_mapping || []).length === 0 ? (
                            <div className="text-center py-3 text-[11px] text-text-muted border border-dashed border-border rounded-md">
                              Default role: user
                            </div>
                          ) : (
                            <div className="border border-border rounded-md overflow-hidden">
                              <table className="w-full table-fixed">
                                <thead className="bg-surface-secondary">
                                  <tr>
                                    <th className="w-[58%] text-left px-3 py-2 text-[10px] font-semibold text-text-muted uppercase tracking-[0.4px]">Group name</th>
                                    <th className="w-[32%] text-left px-3 py-2 text-[10px] font-semibold text-text-muted uppercase tracking-[0.4px]">Role</th>
                                    <th className="w-[10%]"></th>
                                  </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                  {(idpForm.group_role_mapping || []).map((rule, idx) => (
                                    <tr key={idx}>
                                      <td className="px-3 py-2">
                                        <input type="text" value={rule.group_name || ''}
                                          onChange={(e) => updateGroupRule(idx, 'group_name', e.target.value)}
                                          className={idpMonoInputClass}
                                          placeholder="ZTNA-Admins" />
                                      </td>
                                      <td className="px-3 py-2">
                                        <select value={rule.role || 'user'}
                                          onChange={(e) => updateGroupRule(idx, 'role', e.target.value)}
                                          className={idpInputClass}>
                                          <option value="admin">admin</option>
                                          <option value="operator">operator</option>
                                          <option value="auditor">auditor</option>
                                          <option value="user">user</option>
                                        </select>
                                      </td>
                                      <td className="px-2 py-2 text-right">
                                        <button onClick={() => removeGroupRule(idx)}
                                          className="p-1 text-danger hover:bg-danger-muted rounded transition-colors" title="Remove">
                                          <X size={13} />
                                        </button>
                                      </td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
                          )}
                        </div>
                      </div>
                    ) : null}
                  </div>
                </div>

                <div className="flex justify-between items-center gap-4 px-6 py-4 border-t border-border bg-surface-secondary flex-shrink-0">
                  <div className="min-w-0">
                    <button onClick={onTestConnection} disabled={testing || !idpForm.issuer?.trim()}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 text-[11px] font-semibold border border-border rounded text-text-secondary hover:bg-surface-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                      {testing ? <Loader2 size={12} className="animate-spin" /> : <CheckCircle2 size={12} />}
                      {testing ? 'Testing...' : 'Test Discovery'}
                    </button>
                    {testResult && (
                      <div className={`mt-1.5 max-w-[380px] p-1.5 rounded border text-[10px] ${
                        testResult.ok ? 'border-success bg-success-muted' : 'border-danger bg-danger-muted'
                      }`}>
                        {testResult.ok ? (
                          <span className="flex items-center gap-1 text-success font-semibold min-w-0">
                            <CheckCircle2 size={10} className="flex-shrink-0" /> <span className="truncate">OK - {testResult.authorization_endpoint}</span>
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-danger"><AlertCircle size={10} /> {testResult.error}</span>
                        )}
                      </div>
                    )}
                  </div>
                  <div className="flex gap-2">
                    <button onClick={() => setIdpModal(null)}
                      className="px-3 py-1.5 text-[11px] font-semibold text-text-secondary hover:text-text-primary">Cancel</button>
                    <button onClick={onSave}
                      disabled={idpSaving || !idpForm.name || !idpForm.issuer || !idpForm.client_id}
                      className="px-4 py-1.5 text-[11px] font-semibold bg-accent text-white rounded hover:bg-accent-hover disabled:opacity-50 disabled:cursor-not-allowed transition-colors">
                      {idpSaving ? 'Saving...' : 'Save'}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          ) : null}
        </div>
  );
}
