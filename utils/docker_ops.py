import docker
from docker.errors import ImageNotFound, APIError
from rich.console import Console

console = Console()

def get_docker_client():
    """Returns a configured Docker client."""
    try:
        # Use version='auto' to automatically negotiate the API version with the server
        client = docker.from_env(version='auto')
        client.ping()
        return client
    except Exception as e:
        console.print(f"[bold red]Error connecting to Docker daemon:[/bold red] {e}")
        console.print("[yellow]Make sure Docker is running.[/yellow]")
        return None

def pull_image(client, image_name):
    """Pulls the specified image. Returns the image object."""
    try:
        console.print(f"[bold blue]Pulling image {image_name}...[/bold blue]")
        image = client.images.pull(image_name)
        console.print(f"[bold green]Successfully pulled {image_name}[/bold green]")
        return image
    except APIError as e:
        console.print(f"[bold red]Error pulling image:[/bold red] {e}")
        return None

def get_image(client, image_name):
    """Gets an image locally or pulls it if missing."""
    try:
        return client.images.get(image_name)
    except ImageNotFound:
        return pull_image(client, image_name)
    except APIError as e:
        console.print(f"[bold red]Error getting image:[/bold red] {e}")
        return None
