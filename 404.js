(function () {
  'use strict';
  var facts = [
    'Only 5.6% of domains use p=reject',
    'Google and Yahoo now require DMARC',
    'DMARC helps stop exact-domain spoofing',
    'BIMI requires DMARC p=quarantine or p=reject',
    'You can upload XML reports on the homepage'
  ];
  var btn = document.getElementById('factBtn');
  var out = document.getElementById('factOut');
  if (!btn || !out) return;
  btn.addEventListener('click', function () {
    out.textContent = facts[Math.floor(Math.random() * facts.length)];
  });
})();
