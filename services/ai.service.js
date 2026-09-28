const axios = require('axios');

const IA_API_URL = process.env.IA_API_URL || 'https://api-ia-nj05.onrender.com/api';
const IA_API_KEY = process.env.IA_API_KEY || '';

/**
 * Genera una canción completa con letra y acordes usando IA
 * @param {string} title - Título de la canción
 * @param {string} tone - Tono/tonalidad de la canción (ej: C, G, Am, etc.)
 * @param {string} category - Categoría de canto católico (ej: Entrada, Comunión, Salida, etc.)
 * @param {string} artist - Artista/autor de la canción (opcional)
 * @returns {Promise<string>} - Canción en formato ChordPro
 */
async function generateSongWithChords(title, tone = 'C', category = 'Entrada', artist = '') {
    try {
        const artistInfo = artist ? ` de ${artist}` : '';
        const prompt = `Busca la letra ORIGINAL de la canción católica "${title}"${artistInfo} y agrégale acordes en el tono de ${tone}.

IMPORTANTE: 
- Debes buscar y usar la letra ORIGINAL de la canción, NO inventes una nueva
- Si conoces la canción, usa su letra exacta
- Responde ÚNICAMENTE en formato ChordPro
- El formato ChordPro usa corchetes [] para los acordes sobre las letras y llaves {c: } para las secciones

Ejemplo de formato ChordPro:

{c: Intro}
[${tone}]    [G]    [Am]    [F]

{c: Verse 1}
[${tone}]Aquí va la [G]letra ORIGINAL de la can[Am]ción
Con los a[F]cordes sobre las pa[${tone}]labras

{c: Coro}
[Am]Este es el [F]coro
[${tone}]Con acordes [G]también

{c: Salida}
[${tone}]    [G]    [Am]    [F]    [${tone}]

Instrucciones:
- Busca la letra ORIGINAL completa de "${title}"${artistInfo}
- Agrega acordes apropiados para el tono ${tone}
- Identifica las secciones correctas ({c: Intro}, {c: Verse 1}, {c: Verse 2}, {c: Coro}, {c: Puente}, {c: Salida}, etc.)
- Cuando no hay letra (Intro, Salida), deja espacios entre acordes
- NO incluyas {title: } ni {key: } en tu respuesta

Responde SOLO con el formato ChordPro de la canción ORIGINAL, sin explicaciones adicionales.`;

        const headers = {
            'Content-Type': 'application/json'
        };

        if (IA_API_KEY) {
            headers['Authorization'] = `Bearer ${IA_API_KEY}`;
        }

        const response = await axios.post(`${IA_API_URL}/chat`, {
            messages: [
                {
                    role: 'system',
                    content: 'Eres un compositor experto de música litúrgica católica que genera canciones en formato ChordPro. Siempre respondes únicamente en formato ChordPro sin texto adicional. Conoces bien la liturgia católica y las diferentes categorías de cantos.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            model: 'llama-3.3-70b-versatile',
            temperature: 0.8,
            max_tokens: 2000
        }, { headers });

        // Extraer el contenido de la respuesta
        let content = '';
        if (response.data && response.data.choices && response.data.choices[0]) {
            content = response.data.choices[0].message.content;
        } else if (response.data && response.data.content) {
            content = response.data.content;
        } else if (typeof response.data === 'string') {
            content = response.data;
        }

        return content.trim();
    } catch (error) {
        console.error('Error al generar canción con IA:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
        }
        throw new Error(`Error al conectar con la IA: ${error.message}`);
    }
}

/**
 * Autocompleta acordes para una letra existente
 * @param {string} title - Título de la canción
 * @param {string} tone - Tono/tonalidad de la canción
 * @param {string} lyrics - Letra de la canción sin acordes
 * @returns {Promise<string>} - Canción con acordes en formato ChordPro
 */
async function autocompleteChordsForLyrics(title, tone = 'C', lyrics) {
    try {
        const prompt = `Tengo la siguiente letra de una canción católica y necesito que agregues los acordes en formato ChordPro.

Título: ${title}
Tono: ${tone}

Letra:
${lyrics}

IMPORTANTE: Debes responder ÚNICAMENTE en formato ChordPro. El formato ChordPro usa corchetes [] para los acordes sobre las letras.

Instrucciones:

1. Mantén EXACTAMENTE la misma letra que te proporcioné
2. Agrega acordes apropiados para el tono ${tone} usando corchetes []
3. Coloca los acordes sobre las palabras donde deben cambiar
4. Identifica las secciones ({c: Verse}, {c: Chorus}, {c: Bridge}, etc.)
5. no quiero que agregues {title: } y {key: } al inicio

Ejemplo de formato:

{c: Intro}
[${tone}]    [G]    [Am]    [F]

{c: Verse 1}
[${tone}]Aquí va la [G]letra original
Con los a[Am]cordes que tú agre[F]gas

{c: Coro}
[Am]Este es el [F]coro
[${tone}]Con acordes [G]también

Responde SOLO con el formato ChordPro, sin explicaciones adicionales.`;

        const headers = {
            'Content-Type': 'application/json'
        };

        if (IA_API_KEY) {
            headers['Authorization'] = `Bearer ${IA_API_KEY}`;
        }

        const response = await axios.post(`${IA_API_URL}/chat`, {
            messages: [
                {
                    role: 'system',
                    content: 'Eres un músico experto que agrega acordes a letras de canciones católicas en formato ChordPro. Siempre respondes únicamente en formato ChordPro sin texto adicional.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            model: 'llama-3.3-70b-versatile',
            temperature: 0.7,
            max_tokens: 2000
        }, { headers });

        // Extraer el contenido de la respuesta
        let content = '';
        if (response.data && response.data.choices && response.data.choices[0]) {
            content = response.data.choices[0].message.content;
        } else if (response.data && response.data.content) {
            content = response.data.content;
        } else if (typeof response.data === 'string') {
            content = response.data;
        }

        return content.trim();
    } catch (error) {
        console.error('Error al autocompletar acordes con IA:', error.message);
        if (error.response) {
            console.error('Response status:', error.response.status);
            console.error('Response data:', error.response.data);
        }
        throw new Error(`Error al conectar con la IA: ${error.message}`);
    }
}

/**
 * Busca una canción original usando un fragmento de letra como pista
 * @param {string} lyricFragment - Fragmento de letra de la canción a buscar
 * @param {string} artist - Artista/autor de la canción (opcional)
 * @param {string} title - Título de la canción (opcional)
 * @returns {Promise<Object>} - Objeto con la canción encontrada en formato ChordPro y metadata
 */
async function searchSongByLyrics(lyricFragment, artist = '', title = '') {
    try {
        const artistInfo = artist ? ` del artista ${artist}` : '';
        const titleInfo = title ? ` con el título "${title}"` : '';

        const prompt = `Tu tarea es IDENTIFICAR una canción católica existente usando el fragmento de letra proporcionado.

Fragmento de letra:
"${lyricFragment}"
${titleInfo}${artistInfo}

⚠️ REGLAS CRÍTICAS - DEBES SEGUIRLAS ESTRICTAMENTE:

1. SOLO puedes devolver canciones católicas que REALMENTE EXISTEN
2. NO PUEDES INVENTAR, CREAR o GENERAR canciones nuevas
3. Si NO RECONOCES la canción con certeza, DEBES responder con un error
4. La letra debe ser EXACTAMENTE como la canción original, palabra por palabra
5. NO modifiques, parafrasees o "mejores" la letra original

FORMATO DE RESPUESTA:

Si RECONOCES la canción (estás 100% seguro):
{
  "found": true,
  "title": "Título EXACTO de la canción real",
  "artist": "Artista/compositor REAL",
  "key": "Tono sugerido",
  "chordPro": "Letra ORIGINAL COMPLETA con acordes en formato ChordPro"
}

Si NO RECONOCES la canción o tienes dudas:
{
  "found": false,
  "error": "No se pudo identificar la canción con el fragmento proporcionado"
}

Formato ChordPro (solo si encontraste la canción):
- Usa [] para acordes: [C], [G], [Am]
- Usa {c: } para secciones: {c: Verso 1}, {c: Coro}

Ejemplo:
{c: Verso 1}
[C]Letra original [G]exacta
[Am]Sin modificar [F]nada

RECORDATORIO FINAL:
- NO inventes canciones bajo ninguna circunstancia
- Si no estás seguro, responde con "found": false
- La honestidad es más importante que dar una respuesta

Responde SOLO con el objeto JSON, sin texto adicional.`;

        const headers = {
            'Content-Type': 'application/json'
        };

        if (IA_API_KEY) {
            headers['Authorization'] = `Bearer ${IA_API_KEY}`;
        }

        const response = await axios.post(`${IA_API_URL}/chat`, {
            messages: [
                {
                    role: 'system',
                    content: 'Eres un asistente que SOLO identifica canciones católicas REALES que existen. NUNCA inventas o creas canciones nuevas. Si no reconoces una canción, SIEMPRE respondes con un error. Tu integridad es absoluta: prefieres decir "no sé" antes que inventar información. Respondes únicamente en formato JSON.'
                },
                {
                    role: 'user',
                    content: prompt
                }
            ],
            model: 'llama-3.3-70b-versatile',
            temperature: 0.1, // Temperatura muy baja para respuestas más determinísticas y menos creativas
            max_tokens: 2500
        }, { headers });

        // Extraer el contenido de la respuesta
        // La API devuelve el JSON directamente en response.data
        let result;

        console.log('Tipo de response.data:', typeof response.data);
        console.log('Response.data:', JSON.stringify(response.data).substring(0, 200));

        // La API devuelve directamente el objeto JSON, no envuelto en choices
        if (typeof response.data === 'object' && response.data !== null) {
            // Si response.data ya tiene los campos found, title, etc., usarlo directamente
            if ('found' in response.data) {
                result = response.data;
            }
            // Si tiene el formato OpenAI estándar con choices
            else if (response.data.choices && response.data.choices[0]) {
                const content = response.data.choices[0].message.content;
                // Limpiar el contenido por si tiene markdown
                const cleanContent = content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
                result = JSON.parse(cleanContent);
            }
            // Si tiene un campo content
            else if (response.data.content) {
                const cleanContent = response.data.content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
                result = JSON.parse(cleanContent);
            }
            else {
                throw new Error('Formato de respuesta desconocido de la API de IA');
            }
        }
        // Si es un string, parsearlo
        else if (typeof response.data === 'string') {
            const cleanContent = response.data.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
            result = JSON.parse(cleanContent);
        }
        else {
            throw new Error('Formato de respuesta desconocido de la API de IA');
        }

        console.log('Resultado parseado:', result);

        // Verificar si la canción fue encontrada
        if (!result.found || result.found === false) {
            throw new Error(result.error || 'No se pudo identificar la canción con el fragmento proporcionado. Intenta con un fragmento más largo o más específico.');
        }

        // Validar que tenga los campos necesarios
        if (!result.chordPro) {
            throw new Error('La respuesta no contiene el campo chordPro');
        }

        result.author = result.author || result.artist || '';
        return result;
    } catch (error) {
        console.error('❌ Error al buscar canción con IA:');
        console.error('  - Message:', error.message);
        console.error('  - API URL:', IA_API_URL);
        console.error('  - Has API Key:', !!IA_API_KEY);

        if (error.response) {
            console.error('  - Response status:', error.response.status);
            console.error('  - Response data:', JSON.stringify(error.response.data, null, 2));
            console.error('  - Response headers:', error.response.headers);
        } else if (error.request) {
            console.error('  - No response received');
            console.error('  - Request:', error.request);
        }

        // Si el error es que la canción no fue encontrada, usar un mensaje más claro
        if (error.message.includes('No se pudo identificar')) {
            throw error;
        }

        throw new Error(`Error al buscar la canción: ${error.message}`);
    }
}

module.exports = {
    generateSongWithChords,
    autocompleteChordsForLyrics,
    searchSongByLyrics
};
