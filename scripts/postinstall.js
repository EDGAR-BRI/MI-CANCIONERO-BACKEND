const { execSync } = require('child_process');

// 1. Generar cliente de Prisma siempre
console.log('📦 Generando Prisma Client...');
execSync('npx prisma generate', { stdio: 'inherit' });

// 2. Si estamos en el entorno de despliegue de Vercel, sincronizar automáticamente la base de datos
if (process.env.VERCEL) {
    console.log('🚀 Entorno Vercel detectado. Sincronizando esquema con la base de datos PostgreSQL (prisma db push)...');
    try {
        execSync('npx prisma db push --accept-data-loss', { stdio: 'inherit' });
        console.log('✅ Base de datos de producción sincronizada exitosamente.');
    } catch (error) {
        console.warn('⚠️ No se pudo ejecutar prisma db push durante el build de Vercel (típico por IPv6 de Supabase en AWS Lambda):', error.message);
        console.warn('ℹ️ El build continuará normalmente.');
    }
}
