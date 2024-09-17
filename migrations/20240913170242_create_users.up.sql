CREATE TABLE users(
    id bigserial not null primary key,
    email varchar not null unique,
    encrypted_password varchar not null,
    age integer not null,
    gender varchar not null,
    name varchar not null,
    surname varchar not null,
    Description varchar
);