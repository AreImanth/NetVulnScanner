// Static demo only: simulates scan progress client-side. No network requests.
(function () {
  var form = document.getElementById('scanForm');
  var btn = document.getElementById('scanBtn');
  var statusBox = document.getElementById('statusBox');
  var bar = document.getElementById('progressBar');
  var actions = document.getElementById('reportActions');
  var frame = document.getElementById('reportFrame');

  var steps = [
    { pct: 10, msg: 'Queued' },
    { pct: 25, msg: 'Host discovery (nmap -sn)…' },
    { pct: 50, msg: 'Service & version detection (nmap -sV)…' },
    { pct: 75, msg: 'Mapping findings to NVD CVEs…' },
    { pct: 100, msg: 'Scan complete. Rendering report…' }
  ];

  function reset() {
    statusBox.textContent = 'No scan running.';
    bar.style.width = '0';
    actions.classList.remove('visible');
    frame.src = 'about:blank';
  }

  form.addEventListener('submit', function (e) {
    e.preventDefault();
    btn.disabled = true;
    actions.classList.remove('visible');
    frame.src = 'about:blank';
    var i = 0;
    (function next() {
      if (i >= steps.length) {
        actions.classList.add('visible');
        frame.src = './report.html';
        btn.disabled = false;
        return;
      }
      var s = steps[i++];
      statusBox.textContent = s.msg;
      bar.style.width = s.pct + '%';
      setTimeout(next, 900);
    })();
  });

  window.addEventListener('pageshow', function () {
    if (!btn.disabled) return;
    reset();
    btn.disabled = false;
  });
})();
