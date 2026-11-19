FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml constraints.txt ./
COPY src ./src
# constraints.txt pins every dependency to the version the tests ran with (make constraints).
RUN pip install --no-cache-dir --prefix=/install -c constraints.txt .

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /install /usr/local
RUN groupadd --gid 10001 kubeness && useradd --uid 10001 --gid 10001 --no-create-home kubeness
USER 10001:10001
EXPOSE 8080
ENTRYPOINT ["python", "-m", "kubeness"]
