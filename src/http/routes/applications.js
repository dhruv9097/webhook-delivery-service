import { Router } from 'express';
import { prisma } from '../../db.js';
import { ConflictError, NotFoundError } from '../../errors.js';
import { createApplicationSchema, updateApplicationSchema } from '../../schemas/application.js';
import { idParam } from '../../schemas/common.js';
import { requireAuth, requireWrite } from '../middleware/auth.js';
import { generalRateLimit } from '../middleware/rateLimit.js';
import { validate } from '../middleware/validate.js';

export const applicationsRouter = Router();

applicationsRouter.use(requireAuth);
applicationsRouter.use(generalRateLimit);

applicationsRouter.get('/', async (req, res) => {
  const applications = await prisma.application.findMany({
    where: { orgId: req.auth.orgId },
    orderBy: { createdAt: 'desc' },
    include: { _count: { select: { endpoints: true } } },
  });
  res.json({
    data: applications.map(({ _count, ...app }) => ({ ...app, endpointCount: _count.endpoints })),
  });
});

applicationsRouter.post('/', requireWrite('applications:write'), validate({ body: createApplicationSchema }), async (req, res) => {
  const { name, environment } = req.body;

  // Racing requests can both pass a pre-check and still collide, so rely on the
  // unique constraint as the real guard and translate its violation.
  try {
    const application = await prisma.application.create({
      data: { orgId: req.auth.orgId, name, environment },
    });
    res.status(201).json(application);
  } catch (err) {
    if (err.code === 'P2002') {
      throw new ConflictError(`An application named "${name}" already exists in ${environment}`);
    }
    throw err;
  }
});

applicationsRouter.get('/:id', validate({ params: idParam }), async (req, res) => {
  // orgId in the where clause, not a post-fetch check: the tenant boundary
  // belongs in the query so there is no path where it can be forgotten.
  const application = await prisma.application.findFirst({
    where: { id: req.params.id, orgId: req.auth.orgId },
    include: { _count: { select: { endpoints: true, events: true } } },
  });
  if (!application) throw new NotFoundError('Application');

  const { _count, ...rest } = application;
  res.json({ ...rest, endpointCount: _count.endpoints, eventCount: _count.events });
});

applicationsRouter.patch(
  '/:id',
  requireWrite('applications:write'),
  validate({ params: idParam, body: updateApplicationSchema }),
  async (req, res) => {
    const result = await prisma.application.updateMany({
      where: { id: req.params.id, orgId: req.auth.orgId },
      data: req.body,
    });
    if (result.count === 0) throw new NotFoundError('Application');

    res.json(await prisma.application.findUnique({ where: { id: req.params.id } }));
  },
);
