CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recipients (
    email TEXT PRIMARY KEY,
    risk_score INTEGER NOT NULL,
    status TEXT NOT NULL
);
