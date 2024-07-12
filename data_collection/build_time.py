import docker
import json

def get_build_data(image_name):
    client = docker.from_env()
    try:
        image = client.images.get(image_name)
    except docker.errors.ImageNotFound:
        return f"Image '{image_name}' not found."

    # Inspect image to get detailed information
    image_info = client.api.inspect_image(image.id)
    
    build_data = []
    if 'Config' in image_info and 'Labels' in image_info['Config']:
        labels = image_info['Config']['Labels']
        for label, value in labels.items():
            if label.startswith('pkg.'):
                pkg_info = json.loads(value)
                build_data.append({
                    'PkgName': pkg_info.get('PkgName'),
                    'InstalledVersion': pkg_info.get('InstalledVersion'),
                    'Severity': pkg_info.get('Severity'),
                    'Description': pkg_info.get('Description'),
                    'CVSS': pkg_info.get('CVSS')
                })

    return build_data


def main():
    image_name = input("Enter the Docker image name: ")
    build_data = get_build_data(image_name)
    if isinstance(build_data, str):
        print(build_data)
    else:
        print("Build Data:")
        for data in build_data:
            print(json.dumps(data, indent=4))

if __name__ == "__main__":
    main()
