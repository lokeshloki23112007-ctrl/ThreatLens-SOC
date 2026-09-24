INSERT INTO incidents (id, title, severity, status)
VALUES ('inc-001', 'Suspicious phishing email', 'high', 'open');

INSERT INTO campaigns (id, name, status)
VALUES ('camp-001', 'Fake invoice campaign', 'active');

INSERT INTO recipients (email, risk_score, status)
VALUES ('user@example.com', 82, 'pending');
