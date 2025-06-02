az group create --name PolymorphRG --location eastus
az storage account create --name morphstore --resource-group PolymorphRG --sku Standard_LRS
az functionapp create --resource-group PolymorphRG --os-type Linux \
  --consumption-plan-location eastus --runtime python --functions-version 4 \
  --name polymorph-engine --storage-account morphstore
