# DrippShop — бесплатный запуск (Render + Neon + Brevo)

- Сайт: Render, бесплатный Web Service (засыпает при простое, см. ниже).
- База и фото товаров: Neon (бесплатный PostgreSQL). Диск не нужен.
- Письма: по умолчанию не нужны (регистрация без подтверждения). Подтверждение почты включается переменной REQUIRE_EMAIL_VERIFY=1 + Brevo.
- Оплата: ЮKassa (платежи через неё идут с комиссией, нужен статус ИП / самозанятого / юрлица).

## Шаги
1. neon.tech → создать проект → скопировать Connection string → `DATABASE_URL`.
2. brevo.com → зарегистрироваться → SMTP & API → API Keys → создать ключ → `BREVO_KEY`; Senders → добавить и подтвердить свою почту → `MAIL_FROM`.
3. Render → New → Web Service → репозиторий. Build: `npm install`, Start: `npm start`, тариф Free.
4. Переменные из `.env.example`. `BASE_URL` — адрес сайта на Render (https).
5. ЮKassa: HTTP-уведомления → `https://АДРЕС/api/yookassa/webhook`, событие `payment.succeeded`.
6. Чтобы сайт не засыпал: бесплатный пинг на uptimerobot.com раз в 5 минут по адресу `https://АДРЕС/healthz`.

Локально: `DATABASE_URL=... JWT_SECRET=test ADMIN_EMAIL=you@mail.ru npm start`.
Без BREVO_KEY ссылка подтверждения почты печатается в логи.
