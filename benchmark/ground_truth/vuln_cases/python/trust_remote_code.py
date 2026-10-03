from transformers import AutoModel


def load_model(model_name):
    return AutoModel.from_pretrained(model_name, trust_remote_code=True)
