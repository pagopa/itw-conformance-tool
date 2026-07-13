import type { FastifyPluginAsync, FastifyRequest } from 'fastify';

const ALLOWED_EVENTS = ['credential_accepted', 'credential_failure', 'credential_deleted'] as const;

interface NotificationBody {
  notification_id?: string;
  event?: (typeof ALLOWED_EVENTS)[number];
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
          event: { type: 'string', enum: ALLOWED_EVENTS }
        },
        required: ['notification_id', 'event'],
        additionalProperties: false
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
