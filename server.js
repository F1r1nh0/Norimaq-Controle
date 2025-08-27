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

  const {
    OS_Number,
    partName,
    partNumber,
    quantity,
    note,
    createdAt,
    status,
    currentSector,
    routing,
  } = req.body;

  const { error } = await supabase.from("Ordens_Servico").insert([
    {
      OS_Number,
      partName,
      partNumber,
      quantity,
      note,
      createdAt,
      status,
      currentSector,
      routing,
    },
  ]);

  if (error) return res.status(500).json({ error: error.message });

  res.json({ message: "OS criada com sucesso" });
});

// Atualizar progresso da OS (por setor)
app.post("/os/:id/progresso", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { status, quantidade_correta, quantidade_defeito } = req.body;

  const { data: os, error } = await supabase
    .from("Ordens_Servico")
    .select("*")
    .eq("id", id)
    .single();

  if (error || !os) return res.status(404).json({ error: "OS não encontrada" });

  // Atualiza setor atual e status
  const atualizacoes = {
    status,
    currentSector: req.user.role, // setor atual é o usuário que está atualizando
  };

  if (req.user.role === "Almoxarifado") {
    atualizacoes.quantidade_correta = quantidade_correta;
    atualizacoes.quantidade_defeito = quantidade_defeito;
    atualizacoes.status = "Aguardando verificação PCP";
  }

  await supabase.from("Ordens_Servico").update(atualizacoes).eq("id", id);

  res.json({ message: "Progresso atualizado com sucesso" });
});

// PCP finaliza OS
app.post("/os/:id/finalizar", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP")
    return res.status(403).json({ error: "Acesso negado" });

  const { id } = req.params;

  await supabase
    .from("Ordens_Servico")
    .update({ status: "Finalizado" })
    .eq("id", id);

  res.json({ message: "OS finalizada com sucesso" });
});

// Listar todas as OS (somente PCP)
app.get("/os", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP") {
    return res.status(403).json({ error: "Acesso negado" });
  }

  const { data, error } = await supabase
    .from("Ordens_Servico")
    .select("*");

  if (error) return res.status(500).json({ error: error.message });

  res.json(data);
});

// Listar OS do setor correspondente ao usuário logado
app.get("/os/setor", authenticateToken, async (req, res) => {
  const setor = req.user.role; // setor é baseado no "role" do usuário

  const { data, error } = await supabase
    .from("Ordens_Servico")
    .select("*");

  if (error) return res.status(500).json({ error: error.message });

  // Filtra as OS que possuem o setor no roteiro ou no setor atual
  const filtradas = data.filter(
    (os) =>
      os.roteiro.includes(setor) || os.currentSector?.sector === setor
  );

  res.json(filtradas);
});

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
