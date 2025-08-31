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
    orderNumber,
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
      orderNumber,
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

// Editar OS (PATCH)
app.patch("/os/:orderNumber", authenticateToken, async (req, res) => {
  const { orderNumber } = req.params;
  const updates = req.body;

  // PCP pode editar qualquer campo
  if (req.user.role === "PCP") {
    const { error } = await supabase
      .from("Ordens_Servico")
      .update(updates)
      .eq("orderNumber", orderNumber);

    if (error) return res.status(500).json({ error: error.message });
    return res.json({ message: "OS atualizada com sucesso (PCP)" });
  }

  // Almoxarifado só pode editar quantidade
  if (req.user.role === "Almoxarifado") {
    if (!("quantity" in updates)) {
      return res
        .status(400)
        .json({ error: "Somente o campo 'quantity' pode ser atualizado" });
    }

    const { error } = await supabase
      .from("Ordens_Servico")
      .update({ quantity: updates.quantity })
      .eq("orderNumber", orderNumber);

    if (error) return res.status(500).json({ error: error.message });
    return res.json({
      message: "Quantidade atualizada com sucesso (Almoxarifado)",
    });
  }

  // Outros setores não podem editar
  return res
    .status(403)
    .json({ error: "Você não tem permissão para editar esta OS" });
});

// Atualizar progresso da OS (por setor)
app.patch("/os/:orderNumber/progresso", authenticateToken, async (req, res) => {
  const { orderNumber } = req.params;
  const { status, quantidade_correta, quantidade_defeito } = req.body;

  const { data: os, error } = await supabase
    .from("Ordens_Servico")
    .select("*")
    .eq("orderNumber", orderNumber)
    .single();

  if (error || !os) return res.status(404).json({ error: "OS não encontrada" });

  const atualizacoes = {
    status,
    currentSector: req.user.role,
  };

  if (req.user.role === "Almoxarifado") {
    atualizacoes.quantidade_correta = quantidade_correta;
    atualizacoes.quantidade_defeito = quantidade_defeito;
    atualizacoes.status = "Aguardando verificação PCP";
  }

  await supabase
    .from("Ordens_Servico")
    .update(atualizacoes)
    .eq("orderNumber", orderNumber);

  res.json({ message: "Progresso atualizado com sucesso" });
});

// PCP finaliza OS
app.patch("/os/:orderNumber/finalizar", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP")
    return res.status(403).json({ error: "Acesso negado" });

  const { orderNumber } = req.params;

  await supabase
    .from("Ordens_Servico")
    .update({ status: "Finalizado" })
    .eq("orderNumber", orderNumber);

  res.json({ message: "OS finalizada com sucesso" });
});

// Listar todas as OS (somente PCP)
app.get("/os", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP") {
    return res.status(403).json({ error: "Acesso negado" });
  }

  const { data, error } = await supabase.from("Ordens_Servico").select("*");

  if (error) return res.status(500).json({ error: error.message });

  res.json(data);
});

// Listar OS do setor correspondente ao usuário logado
app.get("/os/setor", authenticateToken, async (req, res) => {
  const setor = req.user.role;

  const { data, error } = await supabase.from("Ordens_Servico").select("*");

  if (error) return res.status(500).json({ error: error.message });

  const filtradas = data.filter(
    (os) =>
      os.routing.some((r) => r.sector === setor) ||
      os.currentSector?.sector === setor
  );

  res.json(filtradas);
});

// Buscar OS específica pelo orderNumber
app.get("/os/:orderNumber", authenticateToken, async (req, res) => {
  const orderNumber = Number(req.params.orderNumber); // converte para número

  const { data, error } = await supabase
    .from("Ordens_Servico")
    .select("*")
    .eq("orderNumber", orderNumber)
    .single(); // pega apenas um registro

  if (error || !data)
    return res.status(404).json({ error: "OS não encontrada" });

  res.json(data);
});

app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
