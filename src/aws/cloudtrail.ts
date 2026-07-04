// src/aws/cloudtrail.ts

import {
  CloudTrailClient,
  LookupEventsCommand,
} from "@aws-sdk/client-cloudtrail";

/** Look up Bedrock InvokeModel events from CloudTrail */
export async function lookupBedrockEvents(
  cloudtrail: CloudTrailClient,
  hoursBack: number = 24,
  maxResults: number = 100
): Promise<any[]> {
  const startTime = new Date(Date.now() - hoursBack * 60 * 60 * 1000);
  const events: any[] = [];
  let nextToken: string | undefined;

  do {
    const cmd = new LookupEventsCommand({
      LookupAttributes: [
        {
          AttributeKey: "EventSource",
          AttributeValue: "bedrock.amazonaws.com",
        },
      ],
      StartTime: startTime,
      EndTime: new Date(),
      MaxResults: Math.min(maxResults - events.length, 50),
      NextToken: nextToken,
    });

    const resp = await cloudtrail.send(cmd);
    events.push(...(resp.Events ?? []));
    nextToken = resp.NextToken;

    if (events.length >= maxResults) break;
  } while (nextToken);

  return events.slice(0, maxResults);
}
