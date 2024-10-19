CREATE TABLE users(
    id bigserial not null primary key,
    email text not null unique,
    encrypted_password text not null,
    age integer not null,
    gender text not null,
    name text not null,
    surname text not null,
    Description text
);