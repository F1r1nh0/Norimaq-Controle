import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import supabase from "./supabaseClient.js";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;

// Middleware de autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Login (sem bcrypt)
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const { data: user, error } = await supabase
    .from("users")
    .select("*")
    .eq("username", username)
    .single();

  if (error || !user)
    return res.status(400).json({ error: "Usuário não encontrado" });

  // Comparação direta da senha
  if (password !== user.password) {
    return res.status(401).json({ error: "Senha incorreta" });
  }

  const token = jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "8h" }
  );

  res.json({ token, role: user.role });
});

// Criar OS (apenas PCP)
app.post("/os", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP")
    return res.status(403).json({ error: "Acesso negado" });

  const { numero_os, peca, quantidade, roteiro } = req.body;

  // Inicializa o progresso como "pendente" para cada etapa
  const progresso = {};
  roteiro.forEach((step) => (progresso[step] = "pendente"));

  const { error } = await supabase
    .from("ordens_servico")
    .insert([{ numero_os, peca, quantidade, roteiro, progresso }]);

  if (error) return res.status(500).json({ error: error.message });

  res.json({ message: "OS criada com sucesso" });
});

// Atualizar progresso da OS (por setor)
app.post("/os/:id/progresso", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status, quantidade_correta, quantidade_defeito } = req.body;

  // Busca a OS
  const { data: os, error } = await supabase
    .from("ordens_servico")
    .select("*")
    .eq("id", id)
    .single();

  if (error || !os) return res.status(404).json({ error: "OS não encontrada" });

  // Verifica se o usuário tem permissão para atualizar esta etapa
  const etapaAtual = req.user.role;
  if (!os.roteiro.includes(etapaAtual))
    return res
      .status(403)
      .json({ error: "Usuário não autorizado nesta etapa" });

  // Atualiza o progresso
  const novoProgresso = { ...os.progresso };
  novoProgresso[etapaAtual] = status;

  // Se for Almoxarifado, atualiza quantidade
  const atualizacoes = { progresso: novoProgresso };
  if (etapaAtual === "Almoxarifado") {
    atualizacoes.quantidade_correta = quantidade_correta;
    atualizacoes.quantidade_defeito = quantidade_defeito;
    atualizacoes.status = "Aguardando verificação PCP";
  }

  await supabase.from("ordens_servico").update(atualizacoes).eq("id", id);

  res.json({
    message: "Progresso atualizado com sucesso",
    progresso: novoProgresso,
  });
});

// PCP finaliza OS
app.post("/os/:id/finalizar", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP")
    return res.status(403).json({ error: "Acesso negado" });

  const { id } = req.params;

  await supabase
    .from("ordens_servico")
    .update({ status: "Finalizado" })
    .eq("id", id);

  res.json({ message: "OS finalizada com sucesso" });
});

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
