# ベースイメージにAzure Functions Pythonランタイムを指定
FROM mcr.microsoft.com/azure-functions/python:4-python3.9

# 作業ディレクトリを設定
WORKDIR /home/site/wwwroot

# 必要なファイルをコピー
COPY ./app ./app
COPY ./requirements.txt .

# Pythonパッケージのインストール
RUN pip install --no-cache-dir -r requirements.txt

# Azure Functionsのエントリーポイントを設定
ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true

# Datadog Source Code Integration
ARG DD_GIT_REPOSITORY_URL
ARG DD_GIT_COMMIT_SHA
ENV DD_GIT_REPOSITORY_URL=${DD_GIT_REPOSITORY_URL}
ENV DD_GIT_COMMIT_SHA=${DD_GIT_COMMIT_SHA}
ENV DD_EXCEPTION_REPLAY_ENABLED=true
ENV DD_APPSEC_ENABLED=true
ENV DD_PATCH_MODULES=urllib3
ENV DD_RUNTIME_METRICS_ENABLED=true
ENV DD_RUNTIME_METRICS_RUNTIME_ID_ENABLED=true
ENV DD_PROFILING_ENABLED=true

#ENTRYPOINT ["ddtrace-run"]
#CMD ["/opt/startup/start_nonappservice.sh"]
