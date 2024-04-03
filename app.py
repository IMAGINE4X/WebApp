from PIL import Image
from diffusers import StableDiffusionPipeline
import torch

auth_token = "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"
modelid = "CompVis/stable-diffusion-v1-4"
device = "cuda" if torch.cuda.is_available() else "cpu"

pipe = StableDiffusionPipeline.from_pretrained(
    modelid,
    revision="fp16",
    use_auth_token=auth_token
)

pipe.to(device)

def generate_image(prompt_text):
    output = pipe(prompt_text, guidance_scale=8.5)
    generated_image = output['images'][0]
    return generated_image

user_prompt = input("Enter your prompt text: ")

generated_image = generate_image(user_prompt)
generated_image.show()  # Display the generated image using PIL
