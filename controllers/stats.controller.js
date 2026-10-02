const prisma = require('../prismaClient');
const cache = require('../services/cache.service');

const STATS_TTL = 3600; // 1 hour

exports.getStats = async (req, res) => {
    try {
        let statsData = await cache.get('stats');
        if (!statsData) {
            const [totalSongs, totalCategories, activeSongs, totalUsers, totalAuthors] = await Promise.all([
                prisma.song.count(),
                prisma.category.count(),
                prisma.song.count({ where: { active: true } }),
                prisma.user.count(),
                prisma.author.count(),
            ]);

            statsData = {
                totalSongs,
                totalCategories,
                activeSongs,
                totalUsers,
                totalAuthors,
            };
            await cache.set('stats', statsData, STATS_TTL);
        }

        // Live system health checks (never stale)
        let dbConnected = false;
        let dbLatencyMs = null;
        try {
            const start = Date.now();
            await prisma.$queryRaw`SELECT 1`;
            dbLatencyMs = Date.now() - start;
            dbConnected = true;
        } catch (e) {
            dbConnected = false;
        }

        const redisStatus = await cache.getStatus();

        res.json({
            ...statsData,
            system: {
                database: {
                    connected: dbConnected,
                    status: dbConnected ? 'CONECTADO' : 'DESCONECTADO',
                    latencyMs: dbLatencyMs,
                    engine: 'PostgreSQL (Prisma 7)',
                },
                redis: {
                    connected: redisStatus.connected,
                    status: redisStatus.status,
                    type: redisStatus.type,
                    latencyMs: redisStatus.latencyMs,
                    memoryCacheKeys: redisStatus.memoryCacheKeys,
                },
                server: {
                    status: 'ONLINE',
                    uptime: Math.floor(process.uptime()),
                    nodeEnv: process.env.NODE_ENV || 'development',
                }
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.clearCache = async (req, res) => {
    try {
        await cache.del('stats');
        await cache.delPattern('songs:*');
        await cache.delPattern('*');
        res.json({ success: true, message: 'Caché del sistema purgada exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};
