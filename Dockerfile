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

ENTRYPOINT ["ddtrace-run"]
