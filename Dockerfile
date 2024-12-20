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

# ベースイメージの元のエントリーポイントを取得
RUN echo '#!/bin/bash' >/ddtrace-wrapper.sh && echo 'exec "$@"' >>/ddtrace-wrapper.sh \
    && chmod +x /ddtrace-wrapper.sh

# ddtrace-run を先頭に追加
ENTRYPOINT ["ddtrace-run", "/ddtrace-wrapper.sh"]
