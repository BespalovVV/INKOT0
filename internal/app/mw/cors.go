package mw

import (
	"net/http"

	"github.com/rs/cors"
)

// CorsSettings конфигурирует CORS-политику для вашего сервера.
func CorsSettings() *cors.Cors {
	// Настроим параметры CORS
	c := cors.New(cors.Options{
		// Разрешаем только эти HTTP-методы
		AllowedMethods: []string{
			http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodDelete,
		},
		// Разрешаем только запросы с этого домена (например, фронтенд на порте 3000)
		AllowedOrigins: []string{
			"http://localhost", // Разрешаем запросы только с localhost:3000
		},
		// Разрешаем использование cookies (для передачи авторизационных куков)
		AllowCredentials: true,
		// Указываем допустимые заголовки
		AllowedHeaders: []string{
			"Content-Type",  // Для обработки тела запросов с JSON
			"X-Request-ID",  // Пример заголовка запроса
			"Authorization", // Заголовок для авторизации
			"X-Total-Count", // Для передачи информации о количестве элементов
		},
		// Оставляем в preflight-запросах только те заголовки, которые не должны быть пропущены
		OptionsPassthrough: false,
		// Указываем заголовки, которые будут доступны на клиенте
		ExposedHeaders: []string{
			"Content-Type",  // Доступный для клиента заголовок
			"X-Total-Count", // Для передачи информации о количестве элементов
		},
		// Включаем дебаг для логирования CORS-ответов
		Debug: true,
	})

	return c
}
