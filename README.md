# AUTH SERVICE

### STACK: Express.js, Typescript, Bcrypt, Cookie, JWT, REDIS, PostgreSQL

Authentication service with registration, login, token refresh and logout. Uses JWT for authorization and Redis for storing refresh tokens.

## LAUNCH

Installing dependencies
```bash
npm install
```

Building and running
```bash
npm run start
```

Linter code
```bash
npm run lint:fix
```

## STRUCTURE

```
AUTHSERVICE
└── src
    ├── config
    │   ├── app.config.ts
    │   ├── db.ts
    │   └── redis.config.ts
    ├── controllers
    │   └── authController.ts
    ├── middleware
    │   └── authMiddleware.ts
    ├── routes
    │   └── authRoutes.ts
    ├── service
    │   └── auth.service.ts
    ├── selfsigned_key.pem
    ├── selfsigned.pem
    └── server.ts
├── .env
├── .gitignore
├── eslint.config.mjs
├── package.json
├── README.md
└── tsconfig.json
```

## API ENDPOINTS

| Method | Path              | Description                     |
|-------|-------------------|------------------------------|
| POST  | `/api/register`   | Регистрация пользователя     |
| POST  | `/api/login`      | Вход в систему               |
| POST  | `/api/refresh`    | Обновление access-токена     |
| POST  | `/api/logout`     | Выход из системы             |
| POST  | `/api/send_code`  | Генерация кода поддтверждения|
| POST  | `/api/verify`     | Проверка кода                |
| GET   | `/api/refresh`    | Проверка cookie на наличие токена |
| GET   | `/api/refresh`    | Инициирование регистрации    |

## SECURITY
* Passwords are stored in hashed form (bcrypt)
* HTTP-only cookies are used for refresh tokens
* Access tokens have a limited lifetime
* CSRF protection is implemented