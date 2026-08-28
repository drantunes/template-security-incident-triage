export const dashboardCss = `:root{color-scheme:dark;font-family:system-ui,sans-serif}body{margin:0;background:#10141b;color:#eef3f8}main{max-width:1100px;margin:auto;padding:2rem}.card{border:1px solid #52606d;border-radius:.5rem;padding:1rem;margin:.75rem 0}.fact{border-inline-start:4px solid #4ade80}.hypothesis{border-inline-start:4px solid #facc15}.missing{border-inline-start:4px solid #f87171}:focus-visible{outline:3px solid #8ed0ff;outline-offset:3px}`;

// Kept as a single external, CSP-safe asset. The multiline source makes the live
// projection share the SSR semantics instead of maintaining several fragments.
export const dashboardJs = `(() => {
  const d = document;
  const root = d.querySelector('[data-incident-id]');
  const live = d.querySelector('[data-live-status]');
  if (!root || !window.EventSource) return;

  const id = root.dataset.incidentId;
  const csrf = root.dataset.csrfToken;
  // This is a role capability, deliberately independent of the SSR plan state.
  const canDecide = root.dataset.canDecide === 'true';
  const query = (selector) => d.querySelector(selector);
  const say = (message) => { if (live) live.textContent = message; };
  const sequence = (cursor) => Number(String(cursor || '').split(':').at(-1));
  const connected = (node) => Boolean(node) && node.isConnected !== false;
  const append = (parent, tag, text, data) => {
    const node = d.createElement(tag);
    if (data) Object.assign(node.dataset, data);
    node.textContent = text;
    parent.append(node);
    return node;
  };
  const decisionEligible = (detail) =>
    canDecide &&
    detail.plan &&
    !detail.approval?.decision &&
    detail.incident.status === 'awaiting_approval' &&
    Number.isFinite(Date.parse(detail.plan.expiresAt)) &&
    Date.parse(detail.plan.expiresAt) > Date.now();

  let confirmed = sequence(root.dataset.timelineCursor);
  let received = confirmed;
  let refreshing = false;
  let queued = false;
  let queuedEpoch = 0;
  let epoch = 0;
  let pendingResyncEpoch = 0;
  let retryTimer = null;
  let retryEpoch = 0;
  let retryAttempt = 0;
  let source;
  let dialog = null;
  let form = null;
  let opener = null;

  const fallbackFocus = () =>
    query('[data-triage-projection]')?.querySelector?.('h3') ||
    query('[data-incident-summary]') ||
    root;
  const restoreFocus = () => {
    if (!opener) return;
    const target = connected(opener) ? opener : fallbackFocus();
    if (connected(target)) target.focus?.();
    opener = null;
  };
  const closeDecision = () => {
    const current = dialog || d.getElementById('decision-dialog');
    if (current?.open) current.close();
    restoreFocus();
    dialog = null;
    form = null;
  };

  const decisionError = (message) => {
    const error = query('[data-decision-error]');
    if (error) error.textContent = message;
    say(message);
  };
  const setDecisionBusy = (busy) => {
    if (!form) return;
    if (busy) form.setAttribute('aria-busy', 'true');
    else form.removeAttribute?.('aria-busy');
    for (const button of form.querySelectorAll('button')) button.disabled = busy;
  };

  const bindDecision = () => {
    dialog = d.getElementById('decision-dialog');
    form = query('[data-decision-form]');
    for (const button of d.querySelectorAll('[data-open-decision]')) {
      button.addEventListener('click', () => {
        opener = button;
        dialog?.showModal();
        form?.querySelector('[name="decision"]')?.focus();
      });
    }
    for (const button of d.querySelectorAll('[data-close-dialog]'))
      button.addEventListener('click', closeDecision);
    dialog?.addEventListener('cancel', restoreFocus);
    dialog?.addEventListener('close', restoreFocus);
    dialog?.addEventListener('keydown', (event) => {
      if (event.key !== 'Tab') return;
      const controls = [...dialog.querySelectorAll('button,select,textarea,input')]
        .filter((control) => !control.disabled && control.type !== 'hidden');
      const first = controls[0];
      const last = controls.at(-1);
      if (!first || !last) return;
      if (event.shiftKey && d.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && d.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    });
    form?.addEventListener('submit', async (event) => {
      event.preventDefault();
      const values = new FormData(form);
      const decision = String(values.get('decision'));
      const reason = String(values.get('reason') || '').trim();
      if (decision === 'rejected' && !reason) {
        say('A rejection reason is required.');
        form.querySelector('[name="reason"]')?.focus();
        return;
      }
      setDecisionBusy(true);
      try {
        const response = await fetch(
          '/api/incidents/' + encodeURIComponent(id) + '/approvals',
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'X-CSRF-Token': String(values.get('csrfToken')),
            },
            body: JSON.stringify({
              decision,
              reason: reason || undefined,
              planId: values.get('planId'),
              planHashVersion: Number(values.get('planHashVersion')),
              planHash: values.get('planHash'),
            }),
          },
        );
        if (!response.ok) {
          decisionError('Decision failed. Please retry after refreshing.');
          return;
        }
        await refresh();
      } catch {
        decisionError('Decision could not be sent. Check your connection and retry.');
      } finally {
        setDecisionBusy(false);
      }
    });
  };

  const renderEvidence = (detail) => {
    const host = query('[data-evidence-projection]');
    if (!host) return;
    host.replaceChildren();
    const heading = append(host, 'h3', 'Evidence');
    heading.id = 'evidence-heading';
    for (const item of detail.evidence || [])
      append(
        host,
        'p',
        (item.state === 'missing' ? 'Missing evidence' : item.state) +
          ': ' + item.source + ' / ' + item.provider +
          '; confidence ' + item.confidence + '; observed ' + item.observedAt,
      ).className = item.state;
  };
  const renderTriage = (detail) => {
    const host = query('[data-triage-projection]');
    if (!host) return;
    host.replaceChildren();
    const heading = append(host, 'h3', 'Authoritative containment plan');
    heading.id = 'plan-heading';
    if (detail.triage) {
      append(host, 'p', detail.triage.summary);
      append(host, 'p', 'Runbook: ' + detail.triage.runbook);
      append(host, 'h4', 'Facts');
      for (const fact of detail.triage.facts || [])
        append(host, 'p', 'Fact: ' + fact).className = 'fact';
      append(host, 'h4', 'Hypotheses');
      for (const hypothesis of detail.triage.hypotheses || [])
        append(host, 'p', 'Hypothesis: ' + hypothesis).className = 'hypothesis';
      for (const action of detail.triage.actions || []) {
        const article = append(host, 'article', '');
        append(article, 'h4', action.actionId);
        append(article, 'p', action.type + ' · target ' + action.targetRef);
        append(article, 'p', 'Impact: ' + action.impact);
        append(article, 'p', 'Preconditions: ' + action.preconditions.join('; '));
        append(article, 'p', 'Rollback: ' + action.rollback);
        append(article, 'p', 'Verification: ' + action.verification);
      }
    }
    append(
      host,
      'p',
      detail.plan
        ? 'Hash v' + detail.plan.planHashVersion + ': ' + detail.plan.planHash + '; expires ' + detail.plan.expiresAt
        : 'No current authoritative plan.',
      { planBinding: '' },
    );
    if (decisionEligible(detail)) append(host, 'button', 'Review decision', { openDecision: '' });
    else append(
      host,
      'p',
      detail.plan
        ? 'Decision unavailable: the plan is stale, expired, already decided, or your role is not SOC manager.'
        : 'Decision unavailable: no current authoritative plan exists.',
    ).className = 'muted';
  };
  const renderOperational = (detail) => {
    const host = query('[data-operational-projection]');
    if (!host) return;
    host.replaceChildren();
    const heading = append(host, 'h3', 'Approval and execution outcome');
    heading.id = 'approval-heading';
    append(
      host,
      'p',
      detail.plan
        ? 'Hash v' + detail.plan.planHashVersion + ': ' + detail.plan.planHash + '; expires ' + detail.plan.expiresAt
        : 'No current authoritative plan.',
      { planBinding: '' },
    );
    append(
      host,
      'p',
      detail.approval
        ? 'Approval: ' + (detail.approval.decision || 'pending') +
          (detail.approval.decidedAt ? ' · decided ' + detail.approval.decidedAt : '') +
          (detail.approval.reason ? ' · reason: ' + detail.approval.reason : '')
        : 'No approval has been requested.',
      { approvalStatus: '' },
    );
    const outcome = detail.outcome || { status: 'pending', completedCount: 0, failedCount: 0 };
    append(
      host,
      'p',
      'Outcome: ' + outcome.status + ' · completed ' + outcome.completedCount + ' · failed ' + outcome.failedCount,
      { outcomeStatus: '' },
    );
    const actions = append(host, 'ul', '', { actions: '' });
    for (const action of detail.actions || [])
      append(actions, 'li', action.actionId + ' · ' + action.type + ' · ' + action.status);
  };
  const renderDecision = (detail) => {
    const host = query('[data-decision-host]');
    if (!host) return;
    // Restore focus before replacing the host: a live terminal/expiry update can
    // otherwise detach both the open dialog and its opener.
    if (!decisionEligible(detail)) closeDecision();
    host.replaceChildren();
    if (!decisionEligible(detail)) return;

    const box = d.createElement('dialog');
    box.id = 'decision-dialog';
    box.setAttribute('aria-labelledby', 'decision-heading');
    box.setAttribute('aria-describedby', 'decision-help decision-error');
    const title = append(box, 'h3', 'Confirm containment decision');
    title.id = 'decision-heading';
    const nextForm = d.createElement('form');
    nextForm.dataset.decisionForm = '';
    nextForm.dataset.incidentId = id;
    nextForm.dataset.planBinding =
      detail.plan.planId + ':' + detail.plan.planHashVersion + ':' +
      detail.plan.planHash + ':' + detail.plan.expiresAt;
    for (const [name, value] of [
      ['csrfToken', csrf],
      ['planId', detail.plan.planId],
      ['planHashVersion', String(detail.plan.planHashVersion)],
      ['planHash', detail.plan.planHash],
      ['planExpiresAt', detail.plan.expiresAt],
    ]) {
      const input = d.createElement('input');
      input.type = 'hidden'; input.name = name; input.value = value;
      nextForm.append(input);
    }
    const decisionLabel = append(nextForm, 'label', 'Decision');
    decisionLabel.htmlFor = 'decision-select';
    const select = d.createElement('select');
    select.id = 'decision-select'; select.name = 'decision';
    for (const value of ['approved', 'rejected']) {
      const option = d.createElement('option'); option.value = value;
      option.textContent = value === 'approved' ? 'Approve' : 'Reject'; select.append(option);
    }
    nextForm.append(select);
    const reasonLabel = append(nextForm, 'label', 'Rejection reason (required for rejection, max 2000 characters)');
    reasonLabel.htmlFor = 'decision-reason';
    const reason = d.createElement('textarea');
    reason.id = 'decision-reason'; reason.name = 'reason'; reason.maxLength = 2000;
    reason.setAttribute('aria-describedby', 'decision-help'); nextForm.append(reason);
    const help = append(nextForm, 'p', 'Approval always requires this explicit confirmation.');
    help.id = 'decision-help';
    const error = append(nextForm, 'p', '', { decisionError: '' });
    error.id = 'decision-error';
    error.setAttribute('role', 'alert');
    error.setAttribute('aria-live', 'assertive');
    const confirm = append(nextForm, 'button', 'Confirm decision'); confirm.type = 'submit';
    const cancel = append(nextForm, 'button', 'Cancel', { closeDialog: '' }); cancel.type = 'button';
    box.append(nextForm); host.append(box); bindDecision();
  };
  const render = (detail) => {
    renderEvidence(detail);
    renderTriage(detail);
    renderOperational(detail);
    renderDecision(detail);
  };
  const apply = (detail) => {
    const next = sequence(detail.timelineCursor);
    if (!Number.isSafeInteger(next) || next < confirmed) return false;
    render(detail);
    const timeline = query('[data-timeline]');
    if (timeline) {
      timeline.replaceChildren();
      for (const event of detail.timeline || []) {
        const payload = Object.entries(event.payloadRedacted || {})
          .map(([key, value]) => ' · ' + key + ': ' + String(value))
          .join('');
        append(timeline, 'p', event.sequence + '. ' + event.type + ' · ' + event.occurredAt + payload, { timelineEvent: String(event.sequence) });
      }
    }
    const summary = query('[data-incident-summary]');
    if (summary) summary.textContent = (detail.incident.severity || 'unclassified') + ' · ' + detail.incident.status;
    confirmed = next;
    received = Math.max(received, next);
    root.dataset.timelineCursor = detail.timelineCursor;
    return true;
  };
  async function refresh(requestEpoch = 0) {
    const effectiveEpoch = pendingResyncEpoch || requestEpoch;
    if (refreshing) {
      queued = true;
      queuedEpoch = Math.max(queuedEpoch, effectiveEpoch);
      return false;
    }
    refreshing = true;
    let applied = false;
    try {
      const response = await fetch('/api/incidents/' + encodeURIComponent(id), { cache: 'no-store' });
      if (!response.ok) throw Error('detail refresh failed');
      applied = apply(await response.json());
      if (applied && retryEpoch === effectiveEpoch) {
        retryAttempt = 0;
        if (retryTimer && typeof clearTimeout === 'function') clearTimeout(retryTimer);
        retryTimer = null;
      }
      return applied;
    } catch {
      received = confirmed;
      say('Incident refresh failed. Showing last confirmed state.');
      scheduleRetry(effectiveEpoch);
      return false;
    } finally {
      refreshing = false;
      // A pending generation owns reconnection. A normal refresh queued by a
      // POST while it was in flight is absorbed by its authoritative snapshot.
      if (pendingResyncEpoch && pendingResyncEpoch === effectiveEpoch && applied) {
        pendingResyncEpoch = 0;
        queued = false;
        queuedEpoch = 0;
        source?.close();
        connect();
      } else if (queued) {
        const nextEpoch = queuedEpoch;
        queued = false;
        queuedEpoch = 0;
        void refresh(nextEpoch);
      }
    }
  }
  const scheduleRetry = (requestEpoch) => {
    if (pendingResyncEpoch && requestEpoch !== pendingResyncEpoch) return;
    if (retryEpoch !== requestEpoch) {
      retryEpoch = requestEpoch;
      retryAttempt = 0;
    }
    if (retryTimer || retryAttempt >= 3) return;
    const delay = Math.min(1_000 * 2 ** retryAttempt, 4_000);
    retryAttempt += 1;
    retryTimer = setTimeout(() => {
      retryTimer = null;
      if (!pendingResyncEpoch || pendingResyncEpoch === requestEpoch)
        void refresh(requestEpoch);
    }, delay);
  };
  const requestResync = () => {
    const requestEpoch = ++epoch;
    pendingResyncEpoch = requestEpoch;
    received = confirmed;
    source?.close();
    if (retryTimer) {
      if (typeof clearTimeout === 'function') clearTimeout(retryTimer);
      retryTimer = null;
    }
    retryEpoch = requestEpoch;
    retryAttempt = 0;
    void refresh(requestEpoch);
  };
  const connect = () => {
    source = new EventSource('/api/incidents/' + encodeURIComponent(id) + '/events?resync=stream&after=' + encodeURIComponent(id + ':' + confirmed));
    source.onmessage = (event) => {
      let payload;
      try { payload = JSON.parse(event.data); }
      catch { requestResync(); return; }
      const next = Number(payload.sequence);
      if (!Number.isSafeInteger(next) || next <= confirmed) return;
      if (next !== received + 1) { requestResync(); return; }
      received = next;
      void refresh();
    };
    source.addEventListener('resync', requestResync);
  };
  bindDecision();
  connect();
})();`;
