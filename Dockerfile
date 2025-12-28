# ---- build tools (ffuf, gau, gospider) ----
FROM golang:1.22 AS tools
ENV CGO_ENABLED=0

RUN go install github.com/ffuf/ffuf/v2@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/jaeles-project/gospider@latest

# ---- final lambda image ----
FROM public.ecr.aws/lambda/python:3.12

WORKDIR /var/task

# system deps (only if you truly need them)
RUN microdnf install -y git ca-certificates && microdnf clean all


# copy go tools
COPY --from=tools /go/bin/ffuf /usr/local/bin/ffuf
COPY --from=tools /go/bin/gau /usr/local/bin/gau
COPY --from=tools /go/bin/gospider /usr/local/bin/gospider

# copy project + deps
COPY . .
RUN pip install --no-cache-dir -r requirements.txt

# lambda handler
CMD ["lambda_entry.lambda_handler"]
