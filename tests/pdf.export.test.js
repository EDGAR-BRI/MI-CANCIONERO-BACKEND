const prisma = require('../prismaClient');
const cache = require('../services/cache.service');
const songsController = require('../controllers/songs.controller');
const misaController = require('../controllers/misa.controller');
const pdfService = require('../services/pdf.service');

describe('PDF Export Filename and Header Tests', () => {
    let req;
    let res;

    beforeEach(() => {
        vi.restoreAllMocks();
        vi.spyOn(cache, 'get').mockResolvedValue(null);
        vi.spyOn(cache, 'set').mockResolvedValue(true);

        req = {
            params: { id: '10' },
            query: {}
        };

        res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn().mockReturnThis(),
            setHeader: vi.fn(),
            send: vi.fn().mockReturnThis()
        };
    });

    describe('exportSongPdf', () => {
        const mockSong = {
            id: 10,
            title: 'Pescador de Hombres',
            key: 'C',
            content: '[C]Tú has venido a la [G]orilla',
            author: { name: 'Cesáreo Gabaráin' },
            categories: []
        };

        it('debe generar nombre limpio para cancion con acordes: Nombre_Cancion.pdf', async () => {
            vi.spyOn(prisma.song, 'findUnique').mockResolvedValue(mockSong);
            vi.spyOn(pdfService, 'generateSongPdf').mockResolvedValue(Buffer.from('%PDF-mock'));

            req.query.withChords = 'true';
            await songsController.exportSongPdf(req, res);

            expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'application/pdf');
            expect(res.setHeader).toHaveBeenCalledWith(
                'Content-Disposition',
                expect.stringContaining('filename="Pescador_de_Hombres.pdf"')
            );
        });

        it('debe generar sufijo _letra si la canción es sin acordes: Nombre_Cancion_letra.pdf', async () => {
            vi.spyOn(prisma.song, 'findUnique').mockResolvedValue(mockSong);
            vi.spyOn(pdfService, 'generateSongPdf').mockResolvedValue(Buffer.from('%PDF-mock'));

            req.query.withChords = 'false';
            await songsController.exportSongPdf(req, res);

            expect(res.setHeader).toHaveBeenCalledWith(
                'Content-Disposition',
                expect.stringContaining('filename="Pescador_de_Hombres_letra.pdf"')
            );
        });

        it('debe usar el nombre almacenado en caché en un HIT de caché', async () => {
            vi.spyOn(cache, 'get').mockResolvedValue({
                base64: Buffer.from('%PDF-cached').toString('base64'),
                filename: 'Pescador_de_Hombres.pdf'
            });

            req.query.withChords = 'true';
            await songsController.exportSongPdf(req, res);

            expect(res.setHeader).toHaveBeenCalledWith(
                'Content-Disposition',
                expect.stringContaining('filename="Pescador_de_Hombres.pdf"')
            );
            expect(res.setHeader).toHaveBeenCalledWith('X-Cache', 'HIT');
        });
    });

    describe('exportMisaPdf', () => {
        const mockMisa = {
            id: 25,
            title: 'Misa Dominical',
            dateMisa: new Date('2026-10-18T10:30:00Z'),
            visibility: 'PUBLIC',
            userId: 5,
            misaMoments: [],
            misaSongs: []
        };

        it('debe generar nombre con título, fecha ISO y sufijo _acordes para Misa con acordes', async () => {
            vi.spyOn(prisma.misa, 'findUnique').mockResolvedValue(mockMisa);
            vi.spyOn(pdfService, 'generateMisaPdf').mockResolvedValue(Buffer.from('%PDF-mock-misa'));

            req.query.chords = 'true';
            await misaController.exportMisaPdf(req, res);

            expect(res.setHeader).toHaveBeenCalledWith('Content-Type', 'application/pdf');
            expect(res.setHeader).toHaveBeenCalledWith(
                'Content-Disposition',
                expect.stringContaining('filename="Misa_Dominical_2026-10-18_acordes.pdf"')
            );
        });

        it('debe generar sufijo _letra para Misa en modo solo letra', async () => {
            vi.spyOn(prisma.misa, 'findUnique').mockResolvedValue(mockMisa);
            vi.spyOn(pdfService, 'generateMisaPdf').mockResolvedValue(Buffer.from('%PDF-mock-misa'));

            req.query.chords = 'false';
            await misaController.exportMisaPdf(req, res);

            expect(res.setHeader).toHaveBeenCalledWith(
                'Content-Disposition',
                expect.stringContaining('filename="Misa_Dominical_2026-10-18_letra.pdf"')
            );
        });

        it('no debe duplicar el prefijo Misa si el título ya no lo tiene y debe agregarlo si falta', async () => {
            const misaSinMisa = {
                ...mockMisa,
                title: 'Pascua Juvenil'
            };
            vi.spyOn(prisma.misa, 'findUnique').mockResolvedValue(misaSinMisa);
            vi.spyOn(pdfService, 'generateMisaPdf').mockResolvedValue(Buffer.from('%PDF-mock-misa'));

            req.query.chords = 'true';
            await misaController.exportMisaPdf(req, res);

            expect(res.setHeader).toHaveBeenCalledWith(
                'Content-Disposition',
                expect.stringContaining('filename="Misa_Pascua_Juvenil_2026-10-18_acordes.pdf"')
            );
        });
    });
});
