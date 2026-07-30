import { createHash } from 'node:crypto';

import { createObservedEvent, evaluateUserNeutralEventDescription } from '@itw-conformance-tool/conformance';

import type { FastifyPluginAsync, FastifyRequest } from 'fastify';

const ALLOWED_EVENTS = ['credential_accepted', 'credential_failure', 'credential_deleted'] as const;

interface NotificationBody {
  event?: (typeof ALLOWED_EVENTS)[number];
  event_description?: string;
  notification_id?: string;
}

const sha256Base64Url = (value: string): string => createHash('sha256').update(value, 'utf8').digest('base64url');

const firstHeaderValue = (value: string | string[] | undefined): string | undefined =>
  Array.isArray(value) ? value.at(0) : value;

/**
 * Validates the `event_description` character set required by the IT-Wallet
 * Notification Request spec: `%x20-21 / %x23-5B / %x5D-7E`, i.e. printable
 * ASCII excluding the double-quote (`%x22`) and backslash (`%x5C`)
 * characters. Deliberately narrower than the more permissive `[\x20-\x7E]`
 * range, which would wrongly accept both excluded characters.
 */
export function isValidNotificationEventDescription(value: string): boolean {
  return /^[\x20-\x21\x23-\x5B\x5D-\x7E]*$/.test(value);
}

const notificationRoute: FastifyPluginAsync = async (app) => {
  app.route({
    url: '/notification',
    method: 'POST',
    schema: {
      tags: ['Notification'],
      body: {
        type: 'object',
        properties: {
          notification_id: { type: 'string' },
          event: { type: 'string', enum: ALLOWED_EVENTS },
          event_description: { type: 'string' }
        },
        required: ['notification_id', 'event'],
        // The issuer must ignore parameters it does not recognize instead of
        // rejecting an otherwise-valid Notification Request (see WP_064).
        additionalProperties: true
      }
    },
    handler: async (request: FastifyRequest<{ Body: NotificationBody }>, reply) => {
      const body = request.body;

      if (!body.notification_id || !body.event || !ALLOWED_EVENTS.includes(body.event)) {
        return reply.code(400).send({
          error: 'invalid_notification_request',
          error_description: `Invalid notification request. Allowed events are: ${ALLOWED_EVENTS.join(', ')}`
        });
      }

      const eventDescription = body.event_description;
      const eventDescriptionPresent = typeof eventDescription === 'string';

      if (eventDescriptionPresent && !isValidNotificationEventDescription(eventDescription)) {
        return reply.code(400).send({
          error: 'invalid_notification_request',
          error_description:
            'event_description must only contain characters in the %x20-21 / %x23-5B / %x5D-7E ASCII ranges'
        });
      }

      const userNeutralResult = eventDescriptionPresent
        ? evaluateUserNeutralEventDescription(eventDescription)
        : undefined;

      await app.conformanceEventSink?.emit(
        createObservedEvent({
          name: 'issuer.notification.received',
          correlationId: request.conformance?.correlation?.correlationId ?? null,
          service: 'credential-issuer',
          requestId: request.id,
          diagnostic: {
            endpoint: '/notification',
            method: 'POST',
            contentType: firstHeaderValue(request.headers['content-type']),
            notificationIdSha256: sha256Base64Url(body.notification_id),
            event: body.event,
            // Never store the raw event_description text: WP_064b exists
            // precisely to prevent User behavior/device state information
            // from propagating into diagnostics/reports.
            eventDescriptionPresent,
            eventDescriptionUserNeutral: userNeutralResult?.neutral,
            eventDescriptionReasonCodes: userNeutralResult?.reasonCodes
          }
        })
      );

      request.log.debug(
        { event: body.event, notification_id: body.notification_id },
        'Received valid notification event'
      );

      // Here you can add any additional processing logic for the notification event if needed
      // Currently, we just log the event and return a 204 No Content response.

      return reply.code(204).send();
    }
  });
};

export default notificationRoute;
