import { responses } from "@/app/lib/api/response";
import { CRON_SECRET } from "@/lib/constants";
import { captureTelemetry } from "@/lib/telemetry";
import packageJson from "@/package.json";
import { headers } from "next/headers";
import { prisma } from "@formbricks/database";

export const POST = async () => {
  const headersList = await headers();
  const apiKey = headersList.get("x-api-key");

  if (!apiKey || apiKey !== CRON_SECRET) {
    return responses.notAuthenticatedResponse();
  }

  const [surveyCount, responseCount, userCount] = await Promise.all([
    prisma.survey.count(),
    prisma.response.count(),
    prisma.user.count(),
  ]);

  captureTelemetry("ping", {
    version: packageJson.version,
    surveyCount,
    responseCount,
    userCount,
  });

  return responses.successResponse({}, true);
};
