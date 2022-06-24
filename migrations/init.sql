CREATE TABLE IF NOT EXISTS scores (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  game TEXT NOT NULL,
  username TEXT,
  ip TEXT,
  score REAL NOT NULL
);

CREATE INDEX scores_game_idx ON scores (game, score);
CREATE UNIQUE INDEX scores_game_username_idx ON scores (game, username);