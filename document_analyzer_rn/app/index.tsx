import { Buffer } from 'buffer';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { Inter_400Regular, Inter_600SemiBold, Inter_700Bold, useFonts } from '@expo-google-fonts/inter';
import * as Clipboard from 'expo-clipboard';
import * as Constants from 'expo-constants';
import * as DocumentPicker from 'expo-document-picker';
import * as FileSystem from 'expo-file-system/legacy';
import * as SecureStore from 'expo-secure-store';
import * as Sharing from 'expo-sharing';
import { useEffect, useMemo, useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  PanResponder,
  Platform,
  Pressable,
  SafeAreaView,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

type LabeledValue = { label: string; value: string };

type AnalysisResult = {
  documentType: string;
  summary: string[];
  keyPoints: string[];
  exercises: string[];
  importantDates: LabeledValue[];
  costs: LabeledValue[];
  warnings: string[];
  actionsRequired: string[];
};

type AuthMode = 'login' | 'register';

type AuthResponse = { token: string };

type StoredSession = {
  email: string;
  token: string;
};

type SummarySection = {
  title: string;
  lines: string[];
  emphasize?: boolean;
};

const API_BASE =
  process.env.EXPO_PUBLIC_API_BASE ??
  (Constants.default.expoConfig?.extra as { apiBase?: string } | undefined)?.apiBase ??
  'https://analysispdf-api.onrender.com';
const MAX_CHUNK_CHARS = 1800;
const MAX_ANALYZE_CHUNKS = 8;
const HEALTH_POLL_MS = 60000;

const SESSION_KEY = 'doc_analyzer_session_v2';
const FONT_FAMILY_REGULAR = 'Inter_400Regular';
const FONT_FAMILY_SEMIBOLD = 'Inter_600SemiBold';
const FONT_FAMILY_BOLD = 'Inter_700Bold';

export default function DocumentAnalyzerScreen() {
  const [fontsLoaded] = useFonts({
    Inter_400Regular,
    Inter_600SemiBold,
    Inter_700Bold,
  });

  const [inputText, setInputText] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [status, setStatus] = useState('Pronto. Incolla testo o carica un file.');
  const [isLoading, setIsLoading] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);

  const [authMode, setAuthMode] = useState<AuthMode>('login');
  const [authEmail, setAuthEmail] = useState('');
  const [authPassword, setAuthPassword] = useState('');
  const [session, setSession] = useState<StoredSession | null>(null);
  const [isBooting, setIsBooting] = useState(true);
  const [apiOnline, setApiOnline] = useState<boolean | null>(null);
  const [inputHeight, setInputHeight] = useState(160);

  const canAnalyze = inputText.trim().length > 0 && !isLoading;
  const outputText = useMemo(() => (result ? formatResult(result) : ''), [result]);
  const summarySections = useMemo(() => (result ? buildSummarySections(result) : []), [result]);

  useEffect(() => {
    void bootstrapSession();
  }, []);

  useEffect(() => {
    let cancelled = false;
    const checkServer = async () => {
      try {
        const response = await fetch(`${API_BASE}/health`);
        if (!cancelled) {
          setApiOnline(response.ok);
        }
      } catch {
        if (!cancelled) {
          setApiOnline(false);
        }
      }
    };

    checkServer();
    const interval = setInterval(checkServer, HEALTH_POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, []);

  const inputPanResponder = useMemo(
    () =>
      PanResponder.create({
        onStartShouldSetPanResponder: () => true,
        onPanResponderMove: (_evt, gestureState) => {
          setInputHeight((prev) => clamp(prev + gestureState.dy, 100, 520));
        },
      }),
    [],
  );

  const bootstrapSession = async () => {
    try {
      const saved = await getStoredSession();
      if (saved) {
        const parsed = JSON.parse(saved) as StoredSession;
        if (parsed?.token) {
          setSession(parsed);
        }
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setLastError(message);
    } finally {
      setIsBooting(false);
    }
  };

  const recordError = (error: unknown) => {
    const message = error instanceof Error ? error.message : String(error);
    setLastError(message);
    setStatus('Errore durante l\'operazione.');
    Alert.alert('Errore', message);
  };

  const handleLogin = async () => {
    const email = authEmail.trim().toLowerCase();
    const password = authPassword;
    if (!email || !password) {
      Alert.alert('Dati mancanti', 'Inserisci email e password.');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const detail = await readError(response);
        throw new Error(detail);
      }

      const data = (await response.json()) as AuthResponse;
      const nextSession = { email, token: data.token };
      await setStoredSession(JSON.stringify(nextSession));
      setSession(nextSession);
      setAuthPassword('');
      setLastError(null);
      setStatus('Accesso effettuato.');
    } catch (error) {
      recordError(error);
    }
  };

  const handleRegister = async () => {
    const email = authEmail.trim().toLowerCase();
    const password = authPassword;
    if (!email || !password) {
      Alert.alert('Dati mancanti', 'Inserisci email e password.');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/auth/register`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!response.ok) {
        const detail = await readError(response);
        throw new Error(detail);
      }

      const data = (await response.json()) as AuthResponse;
      const nextSession = { email, token: data.token };
      await setStoredSession(JSON.stringify(nextSession));
      setSession(nextSession);
      setAuthPassword('');
      setLastError(null);
      setStatus('Registrazione completata.');
    } catch (error) {
      recordError(error);
    }
  };

  const handleLogout = async () => {
    await clearStoredSession();
    setSession(null);
    setResult(null);
    setInputText('');
    setStatus('Sessione chiusa.');
  };

  const handleAnalyze = async () => {
    const trimmed = inputText.trim();
    if (!trimmed) {
      Alert.alert('Testo mancante', 'Incolla un testo o carica un file.');
      return;
    }
    if (!session?.token) {
      Alert.alert('Sessione mancante', 'Effettua il login.');
      return;
    }

    setIsLoading(true);
    setStatus('Analisi in corso...');
    setLastError(null);

    try {
      const aiSummary = await summarizeLong(trimmed, session.token);
      const analysis = buildAnalysis(trimmed, aiSummary);
      setResult(analysis);
      setStatus('Analisi completata.');
    } catch (error) {
      recordError(error);
    } finally {
      setIsLoading(false);
    }
  };

  const handlePickFile = async () => {
    try {
      const picked = await DocumentPicker.getDocumentAsync({
        type: ['image/*', 'application/pdf', 'text/plain'],
        copyToCacheDirectory: true,
        base64: false,
        multiple: false,
      });

      if (picked.canceled || !picked.assets?.length) {
        return;
      }

      const asset = picked.assets[0];
      setIsLoading(true);
      setLastError(null);

      if (!session?.token) {
        throw new Error('Effettua il login prima di caricare un file.');
      }

      if (asset.mimeType?.startsWith('image/')) {
        setStatus('OCR immagine via server...');
        const text = await ocrImage(asset, session.token);
        if (!text.trim()) {
          throw new Error('OCR non ha prodotto testo.');
        }
        setInputText(text);
        setStatus('Testo immagine caricato.');
        setResult(null);
        return;
      }

      if (asset.mimeType === 'text/plain' || asset.name?.endsWith('.txt')) {
        setStatus('Carico file di testo...');
        const text = await FileSystem.readAsStringAsync(asset.uri);
        setInputText(text);
        setStatus('Testo caricato.');
        setResult(null);
        return;
      }

      if (asset.mimeType === 'application/pdf' || asset.name?.endsWith('.pdf')) {
        setStatus('Estraggo testo dal PDF...');
        const text = await extractPdfText(asset, session.token);
        setInputText(text);
        setResult(null);
        setStatus('Testo PDF caricato.');
        return;
      }

      Alert.alert('Formato non supportato', 'Usa immagini, PDF o TXT.');
    } catch (error) {
      recordError(error);
    } finally {
      setIsLoading(false);
    }
  };

  const handleCopyOutput = async () => {
    if (!outputText) {
      return;
    }
    await Clipboard.setStringAsync(outputText);
    setStatus('Sintesi copiata.');
  };

  const handleExportPdf = async () => {
    if (!outputText) {
      Alert.alert('Nessun contenuto', 'Genera prima una sintesi.');
      return;
    }
    setIsLoading(true);
    setStatus('Esporto PDF...');
    setLastError(null);

    try {
      const pdfBytes = await buildPdf(outputText);
      const base64 = Buffer.from(pdfBytes).toString('base64');
      const dir = FileSystem.documentDirectory ?? FileSystem.cacheDirectory;
      if (!dir) {
        throw new Error('Cartella documenti non disponibile.');
      }
      const path = `${dir}sintesi-${Date.now()}.pdf`;
      await FileSystem.writeAsStringAsync(path, base64, {
        encoding: FileSystem.EncodingType.Base64,
      });

      if (await Sharing.isAvailableAsync()) {
        await Sharing.shareAsync(path);
        setStatus('PDF esportato.');
      } else {
        setStatus(`PDF salvato: ${path}`);
      }
    } catch (error) {
      recordError(error);
    } finally {
      setIsLoading(false);
    }
  };

  if (isBooting || !fontsLoaded) {
    return (
      <SafeAreaView style={styles.safeArea}>
        <View style={styles.centered}>
          <ActivityIndicator />
          <Text style={styles.centeredText}>Carico sessione...</Text>
        </View>
      </SafeAreaView>
    );
  }

  if (!session) {
    return (
      <SafeAreaView style={styles.safeArea}>
        <ScrollView contentContainerStyle={styles.container}>
          <View style={styles.headerCard}>
            <Text style={styles.headerTitle}>Sintesi Documenti</Text>
            <Text style={styles.headerSubtitle}>Accesso richiesto</Text>
          </View>

          <View style={styles.card}>
            <Text style={styles.cardTitle}>{authMode === 'login' ? 'Login' : 'Registrazione'}</Text>
            <TextInput
              value={authEmail}
              onChangeText={setAuthEmail}
              autoCapitalize="none"
              keyboardType="email-address"
              placeholder="Email"
              placeholderTextColor="#6b6b6b"
              style={styles.textInputSingle}
            />
            <TextInput
              value={authPassword}
              onChangeText={setAuthPassword}
              secureTextEntry
              placeholder="Password"
              placeholderTextColor="#6b6b6b"
              style={styles.textInputSingle}
            />

            <View style={styles.buttonRow}>
              {authMode === 'login' ? (
                <ActionButton label="Accedi" onPress={handleLogin} primary />
              ) : (
                <ActionButton label="Crea account" onPress={handleRegister} primary />
              )}
              <ActionButton
                label={authMode === 'login' ? 'Vai a registrazione' : 'Vai a login'}
                onPress={() => setAuthMode(authMode === 'login' ? 'register' : 'login')}
              />
            </View>
          </View>

          {!!lastError && (
            <View style={styles.errorCard}>
              <Text selectable style={styles.errorText}>
                {lastError}
              </Text>
            </View>
          )}
        </ScrollView>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.safeArea}>
      <ScrollView contentContainerStyle={styles.container}>
        <View style={styles.headerCard}>
          <View style={styles.headerRow}>
            <View style={styles.headerTextBlock}>
              <Text style={styles.headerTitle}>Sintesi Documenti</Text>
              <Text style={styles.headerSubtitle}>{`Utente: ${session.email}`}</Text>
            </View>
            <MiniButton label="Logout" onPress={handleLogout} />
          </View>
          <Text style={styles.headerHint}>React Native + Backend Render. Incolla testo o carica un file.</Text>
        </View>

        <View style={styles.serverCard}>
          <View style={styles.serverRow}>
            <View
              style={[
                styles.serverDot,
                apiOnline == null
                  ? styles.serverDotIdle
                  : apiOnline
                    ? styles.serverDotOk
                    : styles.serverDotError,
              ]}
            />
            <View style={styles.serverTextBlock}>
              <Text style={styles.serverTitle}>API</Text>
              <Text style={styles.serverSubtitle}>{API_BASE}</Text>
            </View>
          </View>
          <Text style={styles.serverHint}>
            {apiOnline == null
              ? 'Verifica in corso...'
              : apiOnline
                ? 'Server raggiungibile.'
                : 'Server non raggiungibile. Verifica URL e deploy.'}
          </Text>
        </View>

        <View style={styles.statusRow}>
          {isLoading ? <ActivityIndicator /> : <View style={styles.statusDot} />}
          <Text style={styles.statusText}>{status}</Text>
        </View>

        {!!lastError && (
          <View style={styles.errorCard}>
            <Text selectable style={styles.errorText}>
              {lastError}
            </Text>
          </View>
        )}

        <View style={styles.card}>
          <Text style={styles.cardTitle}>Testo del documento</Text>
          <TextInput
            multiline
            value={inputText}
            onChangeText={setInputText}
            placeholder="Incolla qui il testo estratto..."
            placeholderTextColor="#6b6b6b"
            style={[styles.textInput, { height: inputHeight }]}
          />
          <View style={styles.resizeHandle} {...inputPanResponder.panHandlers}>
            <View style={styles.resizeBar} />
          </View>

          <View style={styles.buttonRow}>
            <ActionButton label="Carica file" onPress={handlePickFile} disabled={isLoading} />
            <ActionButton
              label="Genera sintesi"
              onPress={handleAnalyze}
              disabled={!canAnalyze}
              primary
            />
          </View>
        </View>

        <View style={styles.cardDark}>
          <View style={styles.cardDarkHeader}>
            <Text style={styles.cardDarkTitle}>Sintesi</Text>
            <View style={styles.buttonRowTight}>
              <MiniButton label="Copia" onPress={handleCopyOutput} disabled={!outputText || isLoading} />
              <MiniButton label="Esporta PDF" onPress={handleExportPdf} disabled={!outputText || isLoading} />
            </View>
          </View>
          {summarySections.length ? (
            <View style={styles.summarySectionsContainer}>
              {summarySections.map((section) => (
                <SummarySectionBlock
                  key={section.title}
                  title={section.title}
                  lines={section.lines}
                  emphasize={section.emphasize}
                />
              ))}
            </View>
          ) : (
            <Text selectable style={styles.outputPlaceholder}>
              Nessuna sintesi disponibile.
            </Text>
          )}
        </View>
      </ScrollView>
    </SafeAreaView>
  );
}

function SummarySectionBlock({
  title,
  lines,
  emphasize,
}: {
  title: string;
  lines: string[];
  emphasize?: boolean;
}) {
  return (
    <View style={[styles.summarySectionCard, emphasize && styles.summarySectionCardEmphasis]}>
      <Text style={[styles.summarySectionTitle, emphasize && styles.summarySectionTitleEmphasis]}>{title}</Text>
      {lines.map((line, index) => (
        <Text key={`${title}-${index}`} selectable style={styles.summarySectionLine}>
          {`\u2022 ${line}`}
        </Text>
      ))}
    </View>
  );
}

function ActionButton({
  label,
  onPress,
  disabled,
  primary,
}: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
  primary?: boolean;
}) {
  return (
    <Pressable
      onPress={onPress}
      disabled={disabled}
      style={[
        styles.actionButton,
        primary ? styles.actionButtonPrimary : styles.actionButtonSecondary,
        disabled && styles.actionButtonDisabled,
      ]}>
      <Text style={[styles.actionButtonText, primary && styles.actionButtonTextPrimary]}>{label}</Text>
    </Pressable>
  );
}

function MiniButton({
  label,
  onPress,
  disabled,
}: {
  label: string;
  onPress: () => void;
  disabled?: boolean;
}) {
  return (
    <Pressable
      onPress={onPress}
      disabled={disabled}
      style={[styles.miniButton, disabled && styles.actionButtonDisabled]}>
      <Text style={styles.miniButtonText}>{label}</Text>
    </Pressable>
  );
}

async function extractPdfText(asset: DocumentPicker.DocumentPickerAsset, token: string): Promise<string> {
  const form = new FormData();
  appendAssetFile(form, asset, 'application/pdf');

  let response;
  try {
    response = await fetch(`${API_BASE}/extract-pdf`, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${token}`,
      },
      body: form,
    });
  } catch {
    throw new Error(`Server non raggiungibile. Verifica ${API_BASE}`);
  }

  if (!response.ok) {
    const detail = await readError(response);
    throw new Error(detail);
  }

  const decoded = (await response.json()) as { text?: string };
  const text = decoded.text?.trim();
  if (!text) {
    throw new Error('Il server non ha estratto testo dal PDF.');
  }
  return text;
}

async function summarizeLong(text: string, token: string): Promise<string | null> {
  const trimmed = text.trim();
  if (!trimmed) {
    return null;
  }
  if (trimmed.length <= MAX_CHUNK_CHARS) {
    try {
      return (await summarizeChunk(trimmed, token)) ?? buildClientFallbackSummary(trimmed);
    } catch {
      return buildClientFallbackSummary(trimmed);
    }
  }

  const chunks = splitIntoChunks(trimmed, MAX_CHUNK_CHARS).slice(0, MAX_ANALYZE_CHUNKS);
  const partials: string[] = [];
  for (const chunk of chunks) {
    try {
      const summary = await summarizeChunk(chunk, token);
      if (summary?.trim()) {
        partials.push(summary.trim());
      }
    } catch {
      // Best-effort: keep good chunks and continue with the next one.
    }
  }
  if (!partials.length) {
    return buildClientFallbackSummary(trimmed);
  }

  const combined = partials.join(' ');
  if (combined.length <= MAX_CHUNK_CHARS) {
    try {
      return (await summarizeChunk(combined, token)) ?? combined;
    } catch {
      return combined;
    }
  }
  return combined;
}

async function summarizeChunk(text: string, token: string): Promise<string | null> {
  const response = await fetch(`${API_BASE}/analyze`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ text }),
  });

  if (!response.ok) {
    const detail = await readError(response);
    throw new Error(detail);
  }

  const decoded = (await response.json()) as { summary?: string };
  return decoded.summary ?? null;
}

async function ocrImage(asset: DocumentPicker.DocumentPickerAsset, token: string): Promise<string> {
  const form = new FormData();
  appendAssetFile(form, asset, 'image/jpeg');

  const response = await fetch(`${API_BASE}/ocr`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
    },
    body: form,
  });

  if (!response.ok) {
    const detail = await readError(response);
    throw new Error(detail);
  }

  const decoded = (await response.json()) as { text?: string };
  return decoded.text ?? '';
}

async function readError(response: Response): Promise<string> {
  if (response.status === 401) {
    return 'Autenticazione fallita. Verifica email/password.';
  }
  if (response.status === 404) {
    return 'Endpoint non trovato (404).';
  }
  if (response.status === 429) {
    return 'Troppe richieste. Riprova tra qualche minuto.';
  }
  try {
    const decoded = await response.json();
    if (decoded?.error) {
      return decoded.error;
    }
  } catch {
    // Ignore JSON parsing errors and fall back to status text.
  }
  return `HTTP ${response.status}`;
}

async function getStoredSession(): Promise<string | null> {
  if (Platform.OS === 'web') {
    return AsyncStorage.getItem(SESSION_KEY);
  }
  if (await SecureStore.isAvailableAsync()) {
    return SecureStore.getItemAsync(SESSION_KEY);
  }
  return AsyncStorage.getItem(SESSION_KEY);
}

async function setStoredSession(value: string): Promise<void> {
  if (Platform.OS === 'web') {
    await AsyncStorage.setItem(SESSION_KEY, value);
    return;
  }
  if (await SecureStore.isAvailableAsync()) {
    await SecureStore.setItemAsync(SESSION_KEY, value);
    return;
  }
  await AsyncStorage.setItem(SESSION_KEY, value);
}

async function clearStoredSession(): Promise<void> {
  if (Platform.OS === 'web') {
    await AsyncStorage.removeItem(SESSION_KEY);
    return;
  }
  if (await SecureStore.isAvailableAsync()) {
    await SecureStore.deleteItemAsync(SESSION_KEY);
    return;
  }
  await AsyncStorage.removeItem(SESSION_KEY);
}

function appendAssetFile(
  form: FormData,
  asset: DocumentPicker.DocumentPickerAsset,
  fallbackMimeType: string,
): void {
  if (Platform.OS === 'web' && asset.file) {
    form.append('file', asset.file, asset.name);
    return;
  }
  form.append('file', {
    uri: asset.uri,
    name: asset.name ?? 'upload.bin',
    type: asset.mimeType ?? fallbackMimeType,
  } as unknown as Blob);
}

function buildAnalysis(input: string, aiSummary: string | null): AnalysisResult {
  const normalized = normalizeForMatching(input);
  const cleanedSummary = extractUsefulSummaryLines(aiSummary);
  const summaryText = cleanedSummary.join(' ');
  const documentType = inferDocumentType(normalized);
  const exercises = extractExercises(normalized, summaryText);
  const dates = extractDates(input);
  const costs = extractCosts(input);
  const warnings = extractWarnings(normalized);
  const actions = extractActions(normalized, input, dates);

  const summary = cleanedSummary.length
    ? cleanedSummary
    : buildFallbackSummary(documentType, dates.length > 0, costs.length > 0, actions.length > 0);

  const keyPoints = buildKeyPoints(
    dates.length > 0,
    costs.length > 0,
    warnings.length > 0,
    actions.length > 0,
    exercises.length > 0,
    summary.join(' '),
  );

  return {
    documentType,
    summary: summary.length ? summary : ['Non specificato'],
    keyPoints: keyPoints.length ? keyPoints : ['Non specificato'],
    exercises: exercises.length ? exercises : ['Nessun esercizio identificato con certezza.'],
    importantDates: dates.length ? dates : [{ label: 'Non specificato', value: 'Non specificato' }],
    costs: costs.length ? costs : [{ label: 'Non specificato', value: 'Non specificato' }],
    warnings: warnings.length ? warnings : ['Nessun avviso rilevante individuato.'],
    actionsRequired: actions.length ? actions : ['Nessuna azione operativa esplicita individuata.'],
  };
}

function inferDocumentType(text: string): string {
  if (
    containsAny(text, ['allenamento', 'workout', 'scheda', 'ripetizioni', 'serie', 'set', 'warm-up', 'defaticamento']) &&
    containsAny(text, ['lunedi', 'martedi', 'mercoledi', 'giovedi', 'venerdi', 'sabato', 'domenica'])
  ) {
    return 'Tabella programma allenamento';
  }
  if (containsAny(text, ['contratto', 'accordo', 'clausola', 'fornitura', 'condizioni contrattuali'])) return 'Contratto';
  if (containsAny(text, ['bolletta', 'fattura', 'totale da pagare', 'consumi'])) return 'Fattura/Bolletta';
  if (containsAny(text, ['diffida', 'messa in mora', 'intimazione', 'ingiunzione'])) return 'Diffida';
  if (containsAny(text, ['privacy', 'trattamento dati', 'gdpr', 'consenso'])) return 'Informativa Privacy';
  if (containsAny(text, ['preventivo', 'offerta economica', 'proposta commerciale'])) return 'Preventivo/Offerta';
  if (containsAny(text, ['verbale', 'delibera', 'assemblea', 'riunione'])) return 'Verbale/Delibera';
  if (containsAny(text, ['comunicazione', 'avviso', 'notifica', 'protocollo', 'raccomandata', 'pec'])) return 'Comunicazione ufficiale';
  if (containsAny(text, ['lettera', 'gentile', 'spett.le', 'cordiali saluti'])) return 'Lettera';
  return 'Non specificato';
}

function extractDates(original: string): LabeledValue[] {
  const patterns = [
    /\b\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}\b/g,
    /\b\d{4}[\/\-.]\d{1,2}[\/\-.]\d{1,2}\b/g,
    /\b\d{1,2}\s+(gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre|ottobre|novembre|dicembre)\s+\d{2,4}\b/gi,
  ];
  const results: LabeledValue[] = [];
  const seen = new Set<string>();

  for (const pattern of patterns) {
    for (const match of original.matchAll(pattern)) {
      const value = match[0]?.trim();
      if (!value || seen.has(value)) continue;
      seen.add(value);
      const context = extractContext(original, match.index ?? 0, 56).toLowerCase();
      if (!isLikelyReferenceDate(value, context)) continue;
      const label = containsAny(context, ['entro', 'scadenza', 'termine', 'ultim']) ? 'Scadenza' : 'Data rilevante';
      results.push({ label, value });
    }
  }

  return dedupeLabeledValues(results).slice(0, 6);
}

function extractCosts(original: string): LabeledValue[] {
  const moneyRegex = /(€\s?\d{1,3}(?:[\.\s]\d{3})*(?:,\d{2})?|\d{1,3}(?:[\.\s]\d{3})*(?:,\d{2})?\s?(?:€|eur|euro)|\b\d+(?:,\d+)?\s?%\b)/gi;
  const results: LabeledValue[] = [];
  const seen = new Set<string>();

  for (const match of original.matchAll(moneyRegex)) {
    const value = match[0]?.trim();
    if (!value || seen.has(value)) continue;
    seen.add(value);
    const context = extractContext(original, match.index ?? 0, 58).toLowerCase();
    let label = 'Importo';
    if (containsAny(context, ['iva', 'imposta', 'tasse'])) label = 'Imposta';
    else if (containsAny(context, ['penale', 'sanzion'])) label = 'Penale';
    else if (containsAny(context, ['interess', 'mora'])) label = 'Interesse';
    else if (containsAny(context, ['rata', 'mensile'])) label = 'Rata';
    else if (containsAny(context, ['sconto', 'ribasso'])) label = 'Sconto';
    results.push({ label, value });
  }

  return dedupeLabeledValues(results).slice(0, 6);
}

function extractWarnings(text: string): string[] {
  const warnings: string[] = [];
  if (containsAny(text, ['penale', 'penali', 'sanzion'])) warnings.push('Prevista penale o sanzione in caso di inadempimento.');
  if (containsAny(text, ['mora', 'interessi', 'interesse'])) warnings.push('Sono citati interessi di mora o costi aggiuntivi.');
  if (containsAny(text, ['sospensione', 'interruzione', 'revoca'])) warnings.push('Possibile sospensione/interruzione del servizio.');
  if (containsAny(text, ['sollecito', 'recupero crediti', 'intimazione'])) warnings.push('Sono indicate azioni di sollecito o recupero crediti.');
  if (containsAny(text, ['decadenza', 'annullamento', 'recesso'])) warnings.push('Esiste rischio di decadenza o annullamento di diritti/servizi.');
  if (containsAny(text, ['termine perentorio', 'entro e non oltre'])) warnings.push('Termini stringenti: superata la data possono esserci conseguenze.');
  if (containsAny(text, ['contenzioso', 'tribunale', 'azione legale'])) warnings.push('Il testo menziona possibili azioni legali.');
  return dedupeAndLimit(warnings, 6);
}

function extractActions(text: string, original: string, dates: LabeledValue[]): string[] {
  const actions: string[] = [];
  if (containsAny(text, ['pagare', 'versare', 'saldo', 'bonifico', 'addebito'])) {
    actions.push('Effettuare il pagamento richiesto entro la scadenza indicata.');
  }
  if (containsAny(text, ['contattare', 'telefonare', 'email', 'e-mail', 'pec', 'call center'])) {
    actions.push('Contattare l\'ente/ufficio ai riferimenti indicati nel documento.');
  }
  if (containsAny(text, ['firmare', 'sottoscrivere', 'siglare'])) {
    actions.push('Firmare il documento e completare la restituzione dove richiesto.');
  }
  if (containsAny(text, ['inviare', 'trasmettere', 'inoltrare', 'allegare'])) {
    actions.push('Inviare la documentazione richiesta con i canali indicati.');
  }
  if (containsAny(text, ['conservare', 'archiviare', 'tenere copia'])) {
    actions.push('Conservare copia del documento e delle ricevute di invio/pagamento.');
  }
  if (containsAny(text, ['presentare ricorso', 'opposizione', 'contestare'])) {
    actions.push('Valutare ricorso/opposizione entro i termini previsti.');
  }
  if (containsAny(text, ['attivare', 'disattivare', 'abilitare'])) {
    actions.push('Eseguire l\'attivazione/disattivazione del servizio secondo istruzioni.');
  }
  if (containsAny(text, ['fornire', 'comunicare', 'dichiarare', 'compilare'])) {
    actions.push('Fornire i dati o compilare i moduli richiesti.');
  }
  if (containsAny(text, ['prendere appuntamento', 'presentarsi'])) {
    actions.push('Prenotare/presentarsi all\'appuntamento indicato nel testo.');
  }
  if (containsAny(text, ['accettare', 'rifiutare'])) {
    actions.push('Esplicitare accettazione o rifiuto entro i tempi previsti.');
  }

  const hasDeadline = dates.some((item) => item.label === 'Scadenza');
  if (actions.length > 0 && hasDeadline) {
    actions.push('Dare priorita alle azioni con scadenza ravvicinata.');
  }
  if (actions.length === 0 && containsAny(normalizeForMatching(original), ['richiesta', 'si invita', 'e necessario'])) {
    actions.push('Verificare attentamente il testo: potrebbe contenere richieste implicite.');
  }

  return dedupeAndLimit(actions, 7);
}

function buildFallbackSummary(documentType: string, hasDates: boolean, hasCosts: boolean, hasActions: boolean): string[] {
  const lines: string[] = [];
  lines.push(
    documentType === 'Non specificato'
      ? 'Il tipo di documento non e\' specificato in modo chiaro.'
      : `Il documento sembra essere una ${documentType.toLowerCase()}.`,
  );
  lines.push(hasCosts ? 'Nel testo sono presenti importi economici.' : 'Non risultano importi chiaramente leggibili.');
  lines.push(hasDates ? 'Sono presenti date potenzialmente rilevanti.' : 'Non emergono date leggibili con certezza.');
  if (hasActions) lines.push('Sono indicate azioni da svolgere.');
  return lines.slice(0, 4);
}

function buildKeyPoints(
  hasDates: boolean,
  hasCosts: boolean,
  hasWarnings: boolean,
  hasActions: boolean,
  hasExercises: boolean,
  aiSummary: string | null,
): string[] {
  const points: string[] = [];
  if (hasCosts) points.push('Sono indicati importi economici nel testo.');
  if (hasDates) points.push('Sono presenti date rilevanti da verificare.');
  if (hasActions) points.push('Sono indicate azioni operative da svolgere.');
  if (!hasActions) points.push('Non risultano azioni operative esplicite.');
  if (hasExercises) points.push('Sono presenti esercizi strutturati nel documento.');
  if (hasWarnings) points.push('Sono menzionate possibili conseguenze o penali.');

  if (!points.length && aiSummary?.trim()) {
    points.push(...extractUsefulSummaryLines(aiSummary).slice(0, 4));
  }
  return dedupeAndLimit(points, 6);
}

function buildSummarySections(result: AnalysisResult): SummarySection[] {
  return [
    { title: 'Tipo documento', lines: [result.documentType] },
    { title: 'Riassunto', lines: result.summary },
    { title: 'Punti chiave', lines: result.keyPoints },
    { title: 'Esercizi rilevati', lines: result.exercises },
    { title: 'Date importanti', lines: result.importantDates.map((item) => `${item.label}: ${item.value}`) },
    { title: 'Costi', lines: result.costs.map((item) => `${item.label}: ${item.value}`) },
    { title: 'Avvisi', lines: result.warnings, emphasize: true },
    { title: 'Azioni richieste', lines: result.actionsRequired, emphasize: true },
  ];
}

function formatResult(result: AnalysisResult): string {
  const sections: [string, string[]][] = buildSummarySections(result).map((section) => [section.title, section.lines]);

  return sections
    .map(([title, lines]) => `${title}:\n${lines.map((line) => `- ${line}`).join('\n')}`)
    .join('\n\n');
}

function splitSentences(text: string): string[] {
  return text
    .replace(/\n+/g, ' ')
    .split(/(?<=[.!?])\s+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

function extractUsefulSummaryLines(summary: string | null): string[] {
  if (!summary?.trim()) return [];

  const lines = summary
    .replace(/\r/g, '\n')
    .split('\n')
    .map((line) => line.replace(/^[-*•\s]+/, '').trim())
    .filter(Boolean)
    .filter((line) => !/^\d+[.)]?$/.test(line))
    .filter((line) => line.length >= 8);

  if (lines.length) return dedupeAndLimit(lines, 5);
  return dedupeAndLimit(splitSentences(summary).filter((line) => line.length >= 8), 5);
}

function normalizeForMatching(text: string): string {
  return text
    .toLowerCase()
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '');
}

function extractContext(source: string, index: number, span: number): string {
  const start = Math.max(0, index - span);
  const end = Math.min(source.length, index + span);
  return source.slice(start, end);
}

function dedupeAndLimit(values: string[], max: number): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const value of values) {
    const key = value.trim().toLowerCase();
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(value.trim());
    if (out.length >= max) break;
  }
  return out;
}

function dedupeLabeledValues(values: LabeledValue[]): LabeledValue[] {
  const seen = new Set<string>();
  const out: LabeledValue[] = [];
  for (const item of values) {
    const key = `${item.label.toLowerCase()}::${item.value.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(item);
  }
  return out;
}

function isLikelyReferenceDate(value: string, context: string): boolean {
  const normalizedValue = value.replace(/\./g, '/').replace(/-/g, '/').trim();
  const dateContextHints = [
    'data',
    'del',
    'al',
    'dal',
    'entro',
    'scadenza',
    'termine',
    'validita',
    'aggiornato',
    'settimana',
    'programma',
    'giorno',
  ];

  const hasContextHint = containsAny(context, dateContextHints);
  const slashFormat = /^(\d{1,2})\/(\d{1,2})\/(\d{4})$/.exec(normalizedValue);
  if (slashFormat) {
    const day = Number(slashFormat[1]);
    const month = Number(slashFormat[2]);
    const year = Number(slashFormat[3]);
    if (year < 2000 || year > 2100) return false;
    if (month < 1 || month > 12) return false;
    if (day < 1 || day > 31) return false;
    return hasContextHint;
  }

  const isoFormat = /^(\d{4})\/(\d{1,2})\/(\d{1,2})$/.exec(normalizedValue);
  if (isoFormat) {
    const year = Number(isoFormat[1]);
    const month = Number(isoFormat[2]);
    const day = Number(isoFormat[3]);
    if (year < 2000 || year > 2100) return false;
    if (month < 1 || month > 12) return false;
    if (day < 1 || day > 31) return false;
    return hasContextHint;
  }

  const monthNameFormat =
    /\b\d{1,2}\s+(gennaio|febbraio|marzo|aprile|maggio|giugno|luglio|agosto|settembre|ottobre|novembre|dicembre)\s+\d{4}\b/i.test(
      normalizedValue,
    );
  if (monthNameFormat) {
    return true;
  }

  return false;
}

function extractExercises(text: string, summaryText: string): string[] {
  const source = `${text}\n${summaryText}`;
  const canonicalExercises: { keys: string[]; label: string }[] = [
    { keys: ['push-up', 'push up', 'piegamenti'], label: 'Push-up / Piegamenti' },
    { keys: ['sit-up', 'sit up', 'addominali'], label: 'Sit-up / Addominali' },
    { keys: ['squat'], label: 'Squat' },
    { keys: ['affondi', 'lunges', 'lunge'], label: 'Affondi' },
    { keys: ['plank'], label: 'Plank' },
    { keys: ['burpee', 'burpees'], label: 'Burpees' },
    { keys: ['trazioni', 'pull-up', 'pull up', 'chin-up'], label: 'Trazioni / Pull-up' },
    { keys: ['dip', 'dips'], label: 'Dip' },
    { keys: ['sprint', 'corsa'], label: 'Sprint / Corsa' },
    { keys: ['jumping jack', 'salti'], label: 'Jumping Jacks / Salti' },
  ];

  const found: string[] = [];
  for (const exercise of canonicalExercises) {
    if (exercise.keys.some((key) => source.includes(key))) {
      found.push(exercise.label);
    }
  }

  return dedupeAndLimit(found, 10);
}

function containsAny(text: string, keywords: string[]): boolean {
  return keywords.some((keyword) => text.includes(keyword));
}

function splitIntoChunks(text: string, maxChars: number): string[] {
  const sentences = text.split(/(?<=[.!?])\s+/);
  if (sentences.length <= 1) {
    return hardChunks(text, maxChars);
  }

  const chunks: string[] = [];
  let current = '';

  for (const sentence of sentences) {
    const trimmed = sentence.trim();
    if (!trimmed) continue;

    if ((current + ' ' + trimmed).trim().length > maxChars) {
      if (current) chunks.push(current.trim());
      if (trimmed.length > maxChars) {
        chunks.push(...hardChunks(trimmed, maxChars));
        current = '';
      } else {
        current = trimmed;
      }
    } else {
      current = `${current} ${trimmed}`.trim();
    }
  }

  if (current) chunks.push(current.trim());
  return chunks;
}

function buildClientFallbackSummary(text: string): string {
  const sentences = splitSentences(text).slice(0, 4);
  if (!sentences.length) {
    return '';
  }
  return sentences.map((line) => `- ${line}`).join('\n');
}

function hardChunks(text: string, maxChars: number): string[] {
  const chunks: string[] = [];
  let index = 0;
  while (index < text.length) {
    const end = Math.min(index + maxChars, text.length);
    chunks.push(text.slice(index, end));
    index = end;
  }
  return chunks;
}

async function buildPdf(content: string): Promise<Uint8Array> {
  // Lazy-load pdf-lib to avoid web startup crashes caused by its transpiled helpers in some bundling environments.
  const { PDFDocument, StandardFonts, rgb } = await import('pdf-lib');
  const pdfDoc = await PDFDocument.create();
  const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

  const lines = wrapLines(content, 92);
  let page = pdfDoc.addPage();
  const { width, height } = page.getSize();
  const fontSize = 12;
  const lineHeight = 16;
  let cursorY = height - 40;

  for (const line of lines) {
    if (cursorY < 40) {
      page = pdfDoc.addPage([width, height]);
      cursorY = height - 40;
    }
    page.drawText(line, {
      x: 32,
      y: cursorY,
      size: fontSize,
      font,
      color: rgb(0.1, 0.18, 0.18),
    });
    cursorY -= lineHeight;
  }

  return pdfDoc.save();
}

function wrapLines(text: string, maxChars: number): string[] {
  const words = text.replace(/\r/g, '').split(/\s+/);
  const lines: string[] = [];
  let current = '';

  for (const word of words) {
    const next = `${current} ${word}`.trim();
    if (next.length > maxChars) {
      if (current) lines.push(current);
      current = word;
    } else {
      current = next;
    }
  }
  if (current) lines.push(current);

  return lines.length ? lines : [''];
}

function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max);
}

const styles = StyleSheet.create({
  safeArea: {
    flex: 1,
    backgroundColor: '#e8efe9',
  },
  centered: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
  },
  centeredText: {
    color: '#1d1d1b',
    fontFamily: FONT_FAMILY_REGULAR,
  },
  container: {
    padding: 20,
    paddingBottom: 40,
    gap: 16,
  },
  headerCard: {
    backgroundColor: '#0e5c5a',
    padding: 20,
    borderRadius: 20,
    shadowColor: '#000',
    shadowOpacity: 0.12,
    shadowRadius: 14,
    shadowOffset: { width: 0, height: 8 },
    elevation: 4,
    gap: 8,
  },
  headerRow: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
  },
  headerTextBlock: {
    flexShrink: 1,
  },
  headerTitle: {
    fontSize: 32,
    fontFamily: FONT_FAMILY_BOLD,
    color: '#ffffff',
  },
  headerSubtitle: {
    marginTop: 4,
    fontSize: 14,
    color: '#d9f1ec',
    fontFamily: FONT_FAMILY_REGULAR,
  },
  headerHint: {
    fontSize: 13,
    color: '#d9f1ec',
    fontFamily: FONT_FAMILY_REGULAR,
  },
  statusRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    paddingHorizontal: 14,
    paddingVertical: 10,
    backgroundColor: '#ffffffcc',
    borderRadius: 16,
    borderWidth: 1,
    borderColor: '#e3d6c6',
  },
  statusDot: {
    width: 10,
    height: 10,
    borderRadius: 10,
    backgroundColor: '#0e5c5a',
  },
  statusText: {
    flex: 1,
    color: '#1d1d1b',
    fontFamily: FONT_FAMILY_REGULAR,
  },
  errorCard: {
    backgroundColor: '#ffe9e6',
    borderColor: '#e7b7ae',
    borderWidth: 1,
    borderRadius: 14,
    padding: 14,
  },
  errorText: {
    color: '#7a271a',
    fontFamily: FONT_FAMILY_REGULAR,
  },
  card: {
    backgroundColor: '#fdf9f3',
    borderRadius: 20,
    borderWidth: 1,
    borderColor: '#e0d4c5',
    padding: 18,
    gap: 12,
  },
  cardTitle: {
    fontSize: 20,
    fontFamily: FONT_FAMILY_BOLD,
    color: '#12201f',
  },
  textInput: {
    backgroundColor: '#f4eee6',
    borderRadius: 14,
    padding: 14,
    textAlignVertical: 'top',
    fontSize: 15,
    color: '#1d1d1b',
    fontFamily: FONT_FAMILY_REGULAR,
  },
  textInputSingle: {
    minHeight: 48,
    backgroundColor: '#f4eee6',
    borderRadius: 14,
    paddingHorizontal: 14,
    paddingVertical: 10,
    fontSize: 15,
    color: '#1d1d1b',
    fontFamily: FONT_FAMILY_REGULAR,
  },
  buttonRow: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
  },
  actionButton: {
    paddingHorizontal: 16,
    paddingVertical: 12,
    borderRadius: 14,
  },
  actionButtonPrimary: {
    backgroundColor: '#0e5c5a',
  },
  actionButtonSecondary: {
    backgroundColor: '#f2a03d',
  },
  actionButtonDisabled: {
    opacity: 0.5,
  },
  actionButtonText: {
    fontFamily: FONT_FAMILY_SEMIBOLD,
    color: '#1f2a29',
  },
  actionButtonTextPrimary: {
    color: '#ffffff',
  },
  cardDark: {
    backgroundColor: '#112526',
    borderRadius: 20,
    padding: 18,
    gap: 12,
  },
  cardDarkHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    gap: 12,
  },
  cardDarkTitle: {
    fontSize: 20,
    fontFamily: FONT_FAMILY_BOLD,
    color: '#ffffff',
  },
  buttonRowTight: {
    flexDirection: 'row',
    gap: 8,
  },
  miniButton: {
    paddingHorizontal: 12,
    paddingVertical: 8,
    backgroundColor: '#0e5c5a',
    borderRadius: 12,
  },
  miniButtonText: {
    color: '#ffffff',
    fontFamily: FONT_FAMILY_SEMIBOLD,
    fontSize: 12,
  },
  summarySectionsContainer: {
    gap: 10,
  },
  summarySectionCard: {
    borderRadius: 14,
    borderWidth: 1,
    borderColor: '#244446',
    padding: 12,
    backgroundColor: '#0b1f20',
    gap: 6,
  },
  summarySectionCardEmphasis: {
    borderColor: '#f2cc60',
    backgroundColor: '#1f2e22',
  },
  summarySectionTitle: {
    color: '#f2cc60',
    fontFamily: FONT_FAMILY_BOLD,
    fontSize: 16,
  },
  summarySectionTitleEmphasis: {
    color: '#ffda6a',
  },
  summarySectionLine: {
    color: '#c9e8e2',
    fontFamily: FONT_FAMILY_REGULAR,
    fontSize: 14,
    lineHeight: 21,
  },
  outputPlaceholder: {
    color: '#b7e3dd',
    fontFamily: FONT_FAMILY_REGULAR,
    fontSize: 14,
    lineHeight: 20,
  },
  serverCard: {
    backgroundColor: '#f1f6f4',
    borderRadius: 18,
    borderWidth: 1,
    borderColor: '#d7e6df',
    padding: 14,
    gap: 6,
  },
  serverRow: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
  },
  serverDot: {
    width: 12,
    height: 12,
    borderRadius: 12,
  },
  serverDotIdle: {
    backgroundColor: '#9aa7a5',
  },
  serverDotOk: {
    backgroundColor: '#22c55e',
  },
  serverDotError: {
    backgroundColor: '#ef4444',
  },
  serverTextBlock: {
    flex: 1,
  },
  serverTitle: {
    fontSize: 14,
    fontFamily: FONT_FAMILY_SEMIBOLD,
    color: '#102221',
  },
  serverSubtitle: {
    fontSize: 12,
    color: '#334845',
    fontFamily: FONT_FAMILY_REGULAR,
  },
  serverHint: {
    fontSize: 12,
    color: '#334845',
    fontFamily: FONT_FAMILY_REGULAR,
  },
  resizeHandle: {
    height: 22,
    alignItems: 'center',
    justifyContent: 'center',
  },
  resizeBar: {
    width: 46,
    height: 4,
    borderRadius: 4,
    backgroundColor: '#b9aca0',
  },
});
