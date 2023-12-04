# anchore-notify Github Action

Foobar is a Python library for dealing with word pluralization.

## Usage

Create a Github Action workflow yaml as such...

```yaml
name: Anchore Scan
on: [push, pull_request]

jobs:
  run:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 #v4.1.1

      - name: build container image
        run: docker build . --file ./Dockerfile --tag localbuild/yourimage:latest

      - uses: anchore/scan-action@896d5f410043987c8fe18f60d91bf199e436840c # v3.3.8
        id: scan
        with:
          image: "localbuild/yourimage:latest"
          fail-build: false # default is true
          # severity-cutoff: high # default is medium
      
      - name: run anchore-notify
        uses: chronograph-pe/anchore-notify@0e3bb32defe79fa905d64c7181669abdf5e82c43 #v1
        with:
          sarif_data: ${{ steps.scan.outputs.sarif }}
          severity_cutoff_num: 10
          slack_token: ${{ secrets.SLACK_BOT_TOKEN }} 
          slack_channel: ${{ secrets.SLACK_CHANNEL }} 
          github_run_url: ${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}
          report_name: yourimage_report_name

      - name: create step summary
        run: cat ./job_summary.md >> $GITHUB_STEP_SUMMARY


```

## Action Inputs

- sarif_data
  - Description: Anchore SARIF data
  - Required: True
- severity_cutoff_num
  - Description: Anchore severity number threshold that will generate notifications
  - Default: 8
  - Required: False
- slack_token
  - Description: Your Slack bot token with permissions to post to a channel
  - Required: False
- slack_channel
  - Description: The Slack channel ID you want to send messages to
  - Required: False
- report_name
  - Description: A name for your report that will be included in the notifications
  - Required: True
- github_run_url
  - Description: The current workflow run URL to be used in notifications to view job summary
  - Required: True


## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License

[MIT](https://choosealicense.com/licenses/mit/)