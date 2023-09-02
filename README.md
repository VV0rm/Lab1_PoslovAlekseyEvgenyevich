Проверка данных пользователя при регистрации.

Реализация метода проверки данных пользователя при регистрации.
Входные данные:
- Строка1 (логин). В формате телефона (+x-xxx-xxx-xxxx), электронной почты (xxx@xxx.xxx)
или просто строка символов. Разделены все три варианта возможной регистрации.
- Строка2 (пароль).
- Строка3 (подтверждение пароля)
Ограничения: логин в форме телефона и почты должен валидироваться
согласно указанным правилам для телефона и почты.
Ограничения: в логине в форме строки должно быть минимум 5 символов,
только латиница, цифры и знак подчеркивания _.
Ограничения: логин не должен совпадать с логинами из
предустановленного списка строк.
Ограничения: в пароле должно быть минимум 7 символов, только кириллица,
цифры и спецсимволы. Обязательно присутствие минимум одной буквы в
верхнем и нижнем регистре, одной цифры и одного спецсимвола.
Ограничения: пароль и подтверждение пароля должны совпадать.
Выходные данные:
- Строка1 (результат). «True» - в случае успеха, «False» - в случае ошибки.
- Строка2 (сообщение). Пустая строка в случае успешной регистрации; в
случае неуспешной регистрации - текст ошибки, поясняющий причину
неуспеха.

- Логирование успешной регистрации пользователя: дата-время запроса,
логин, маскированный пароль, маскированное подтверждение пароля,
фраза «Успешная регистрация».
- Логирование неуспешной регистрации пользователя: дата-время запроса,
логин, маскированный пароль, маскированное подтверждение пароля,
текст ошибки (включая трассировку стека исключения, если есть).