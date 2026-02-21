(function() {
  var rows = document.querySelectorAll('tr.ann-sending');
  if (!rows.length) return;

  var csrfInput = document.querySelector('input[name="csrf_token"]');
  var token = csrfInput ? csrfInput.value : '';

  function pollStatus() {
    rows.forEach(function(row) {
      var annId = row.getAttribute('data-ann-id');
      if (!annId) return;

      fetch('/api/announcement-status/' + annId, {
        headers: {'X-CSRF-Token': token}
      })
      .then(function(r) { return r.json(); })
      .then(function(data) {
        var sentEl = row.querySelector('.ann-sent');
        var failedEl = row.querySelector('.ann-failed');
        var pendingEl = row.querySelector('.ann-pending');
        var statusEl = row.querySelector('.ann-status');
        var completedEl = row.querySelector('.ann-completed-at');

        if (sentEl) sentEl.textContent = data.sent_count;
        if (failedEl) failedEl.textContent = data.failed_count;
        if (pendingEl) {
          var pending = data.total_users - data.sent_count - data.failed_count;
          pendingEl.textContent = Math.max(0, pending);
        }

        if (data.status !== 'sending') {
          row.classList.remove('ann-sending');
          if (statusEl) {
            statusEl.className = 'ann-status tag ' + (data.status === 'completed' ? 'ok' : 'err');
            statusEl.textContent = data.status === 'completed' ? 'Completato' : 'Fermato';
          }
          if (completedEl && data.completed_at) {
            completedEl.textContent = data.completed_at;
          }
          var actionTd = row.querySelector('td:last-child');
          if (actionTd) actionTd.textContent = '-';
        }
      })
      .catch(function() {});
    });

    rows = document.querySelectorAll('tr.ann-sending');
    if (rows.length > 0) {
      setTimeout(pollStatus, 3000);
    }
  }

  setTimeout(pollStatus, 2000);
})();
