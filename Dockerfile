FROM python:3.12-alpine3.23
WORKDIR /app
RUN apk update \
    && apk upgrade \
    && pip install --no-cache-dir poetry==2.2.0
RUN poetry config virtualenvs.create false
COPY pyproject.toml poetry.lock /app/
RUN poetry install --no-interaction --no-ansi --no-root
COPY . .
CMD poetry run python main.py