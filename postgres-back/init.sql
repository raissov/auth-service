CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS users (
    id bigserial,
    public_id uuid DEFAULT uuid_generate_v4() NOT NULL ,
    email text UNIQUE NOT NULL ,
    password text NOT NULL
);