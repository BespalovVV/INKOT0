# Используем официальный образ Go как базовый
FROM golang:1.23 AS builder

# Устанавливаем рабочую директорию
WORKDIR /cmd/apiserver

# Копируем go.mod и go.sum для кеширования зависимостей
COPY backend/go.mod backend/go.sum ./

# Загружаем зависимости
RUN go mod tidy

# Копируем исходный код приложения
COPY backend .

# Компилируем Go приложение
RUN go build -o main ./cmd/apiserver


# Запускаем приложение
CMD ["./main"]