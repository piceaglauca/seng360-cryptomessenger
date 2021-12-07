CREATE TABLE conversation(
    id PRIMARY KEY,
    peer
);

CREATE TABLE message(
    id PRIMARY KEY,
    conversation_id,
    body,
    tag,
    timestamp,
    FOREIGN KEY (conversation_id) REFERENCES conversation(id)
);
