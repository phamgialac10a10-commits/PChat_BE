

Table: roles
| Column      | Type          | Constraints / Notes       |
| ----------- | ------------- | ------------------------- |
| id          | BIGINT        | PK, AUTO_INCREMENT        |
| name        | VARCHAR(255)  | NOT NULL, UNIQUE          |
| description | VARCHAR(1000) | NULLABLE                  |
| created_at  | DATETIME      | DEFAULT CURRENT_TIMESTAMP |
| updated_at  | DATETIME      | AUTO UPDATE               |

Table: users
| Column             | Type         | Constraints / Notes                |
| ------------------ | ------------ | ---------------------------------- |
| id                 | BIGINT       | PK, AUTO_INCREMENT                 |
| fullname           | VARCHAR(255) | NOT NULL                           |
| phone              | VARCHAR(20)  | NULLABLE                           |
| email              | VARCHAR(255) | NOT NULL, UNIQUE                   |
| date_of_birth      | DATE         | NULLABLE                           |
| is_active          | BOOLEAN      | DEFAULT TRUE                       |
| access_token       | TEXT         | NULLABLE (JWT)                     |
| refresh_token      | TEXT         | NULLABLE (JWT)                     |
| access_expires_at  | DATETIME     | NULLABLE                           |
| refresh_expires_at | DATETIME     | NULLABLE                           |
| role_id            | BIGINT       | Role reference (NO FK – by design) |
| created_at         | DATETIME     | DEFAULT CURRENT_TIMESTAMP          |
| updated_at         | DATETIME     | AUTO UPDATE                        |

Table: rooms
| Column     | Type                    | Constraints / Notes       |
| ---------- | ----------------------- | ------------------------- |
| id         | BIGINT                  | PK, AUTO_INCREMENT        |
| name       | VARCHAR(255)            | NOT NULL                  |
| type       | ENUM('private','group') | DEFAULT 'private'         |
| created_at | DATETIME                | DEFAULT CURRENT_TIMESTAMP |
| updated_at | DATETIME                | AUTO UPDATE               |


Table: room_members
| Column    | Type     | Constraints / Notes                   |
| --------- | -------- | ------------------------------------- |
| id        | BIGINT   | PK, AUTO_INCREMENT                    |
| user_id   | BIGINT   | NOT NULL                              |
| room_id   | BIGINT   | NOT NULL                              |
| joined_at | DATETIME | DEFAULT CURRENT_TIMESTAMP             |
| UNIQUE    | —        | (user_id, room_id) – tránh join trùng |







