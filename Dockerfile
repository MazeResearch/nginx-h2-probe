# The tool is stdlib-only; the image is just a portable runtime that also
# solves the deployment problem: run it where it has a direct TCP path to
# the nginx origins you want to test.
FROM python:3.12-alpine

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir .

# non-root
USER nobody

ENTRYPOINT ["nginx-h2-probe"]
CMD ["--help"]