FROM node:22-alpine AS frontend-build

WORKDIR /frontend

COPY package.json package-lock.json vite.config.js index.html ./
COPY src ./src
COPY public ./public

RUN npm ci && npm run build


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    ENV=production

WORKDIR /app

RUN addgroup --system wedo && adduser --system --ingroup wedo wedo

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./main.py
COPY --from=frontend-build /frontend/dist ./dist

RUN mkdir -p /app/data && chown -R wedo:wedo /app

USER wedo

EXPOSE 8080

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
