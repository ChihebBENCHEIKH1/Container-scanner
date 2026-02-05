package utils

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/moby/moby/api/types/image"
	"github.com/moby/moby/client"
)

// GetDockerClient returns a configured Docker client.
func GetDockerClient() (*client.Client, error) {
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("error connecting to Docker daemon: %w", err)
	}
	return cli, nil
}

// PullImage pulls the specified image.
func PullImage(cli *client.Client, imageName string) error {
	fmt.Printf("Pulling image %s...\n", imageName)
	response, err := cli.ImagePull(context.Background(), imageName, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("error pulling image: %w", err)
	}
	defer response.Close()
	io.Copy(os.Stdout, response)
	return nil
}

// GetImage checks if an image exists locally, pulling it if missing.
func GetImage(cli *client.Client, imageName string) (image.Summary, error) {
	images, err := cli.ImageList(context.Background(), client.ImageListOptions{})
	if err != nil {
		return image.Summary{}, err
	}

	for _, img := range images.Items {
		for _, tag := range img.RepoTags {
			if tag == imageName {
				return img, nil
			}
		}
	}

	err = PullImage(cli, imageName)
	if err != nil {
		return image.Summary{}, err
	}

	// Re-search after pull
	return GetImage(cli, imageName)
}
// ListImages returns a list of all images available on the host.
func ListImages(cli *client.Client) ([]image.Summary, error) {
	images, err := cli.ImageList(context.Background(), client.ImageListOptions{})
	if err != nil {
		return nil, err
	}
	return images.Items, nil
}
