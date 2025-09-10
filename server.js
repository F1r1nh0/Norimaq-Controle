import express from "express";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();
const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);
// Middleware de autenticação
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.status(401).json({ error: "Token não fornecido" });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ error: "Token expirado" });
      }
      return res.status(403).json({ error: "Token inválido" });
    }
    req.user = user;
    next();
  });
}

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("username", username)
      .single();

    if (error || !user) {
      return res.status(400).json({ error: "Usuário não encontrado" });
    }

    if (password !== user.password) {
      return res.status(401).json({ error: "Senha incorreta" });
    }

    // Access token - expira rápido
    const accessToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    // Refresh token - expira mais lento
    const refreshToken = jwt.sign(
      { id: user.id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: "7d" }
    );

    // Salva refresh token no banco
    await supabase.from("users").update({ refreshToken }).eq("id", user.id);

    res.json({ accessToken, refreshToken, role: user.role });
  } catch (err) {
    console.error("Erro inesperado no login:", err.message);
    res.status(500).json({ error: "Erro interno no servidor" });
  }
});

// Rota para renovar token
app.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken)
    return res.status(401).json({ error: "Refresh token não fornecido" });

  // Verifica se o refresh token existe no banco
  const { data: user } = await supabase
    .from("users")
    .select("*")
    .eq("refreshToken", refreshToken)
    .single();

  if (!user) return res.status(403).json({ error: "Refresh token inválido" });

  jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET, (err) => {
    if (err)
      return res
        .status(403)
        .json({ error: "Refresh token inválido ou expirado" });

    // Gera novo access token
    const newAccessToken = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "15m" }
    );

    res.json({ accessToken: newAccessToken });
  });
});

// Verifica se o token é válido
app.get("/auth", authenticateToken, (req, res) => {
  res.json({
    valid: true,
    user: req.user, // { id, role }
  });
});

// Logout → remove refresh token
app.post("/logout", async (req, res) => {
  const { refreshToken } = req.body;
  await supabase
    .from("users")
    .update({ refreshToken: null })
    .eq("refreshToken", refreshToken);

  res.json({ message: "Logout realizado com sucesso" });
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
    priority,
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
      priority,
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

  // Só PCP ou ALMOXARIFADO podem editar
  if (req.user.role === "PCP" || req.user.role === "ALMOXARIFADO") {
    const { data, error } = await supabase
      .from("Ordens_Servico")
      .update(updates)
      .eq("orderNumber", orderNumber)
      .select("*") // retorna os campos atualizados
      .single();   // garante apenas 1 registro

    if (error) return res.status(500).json({ error: error.message });

    return res.json({
      message: `OS atualizada com sucesso (${req.user.role})`,
      updatedOS: data, // retorna a OS editada
    });
  }

  // Outros setores não podem editar
  return res
    .status(403)
    .json({ error: "Você não tem permissão para editar esta OS" });
});

// Deletar OS (apenas PCP)
app.delete("/os/:orderNumber", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP") {
    return res.status(403).json({ error: "Apenas o PCP pode excluir uma OS" });
  }

  const { orderNumber } = req.params;

  const { error } = await supabase
    .from("Ordens_Servico")
    .delete()
    .eq("orderNumber", orderNumber);

  if (error) return res.status(500).json({ error: error.message });

  res.json({ message: `OS ${orderNumber} excluída com sucesso` });
});

// Atualizar progresso da OS (por setor) (retirar)
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

// PCP finaliza OS (retirar)
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

  // Agora filtra apenas pelo setor atual
  const filtradas = data.filter(
  (os) => os.currentSector?.sector === setor
);

  res.json(filtradas);
});

// Buscar OS específica pelo orderNumber
app.get("/os/:orderNumber/ler", authenticateToken, async (req, res) => {
  const orderNumber = req.params.orderNumber;

  const { data, error } = await supabase
    .from("Ordens_Servico")
    .select("*")
    .eq("orderNumber", orderNumber)
    .single(); // pega apenas um registro

  if (error || !data)
    return res.status(404).json({ error: "OS não encontrada" });

  res.json(data);
});

// Setor registra produção
app.patch("/os/:orderNumber/producao", authenticateToken, async (req, res) => {
  const { orderNumber } = req.params;
  const { producedQuantity, defectiveQuantity } = req.body;

  // Qualquer setor exceto PCP pode registrar
  if (req.user.role === "PCP") {
    return res.status(403).json({ error: "PCP não deve registrar produção, apenas validar" });
  }

  const { data: os, error } = await supabase
    .from("Ordens_Servico")
    .select("*")
    .eq("orderNumber", orderNumber)
    .single();

  if (error || !os) return res.status(404).json({ error: "OS não encontrada" });

  const atualizacoes = {
    currentQuantity: producedQuantity,
    defectiveQuantity,
    status: "Aguardando verificação PCP",
    pendingSector: req.user.role, // quem registrou a produção
  };

  const { data: updated, error: updateError } = await supabase
    .from("Ordens_Servico")
    .update(atualizacoes)
    .eq("orderNumber", orderNumber)
    .select("*")
    .single();

  if (updateError) return res.status(500).json({ error: updateError.message });

  res.json({
    message: `Produção registrada por ${req.user.role}. Aguardando PCP.`,
    os: updated,
  });
});

// PCP valida produção e libera próximo setor
app.patch("/os/:orderNumber/validar", authenticateToken, async (req, res) => {
  if (req.user.role !== "PCP") {
    return res.status(403).json({ error: "Apenas o PCP pode validar a produção" });
  }

  const { orderNumber } = req.params;
  const { aprovado } = req.body; // true ou false

  const { data: os, error } = await supabase
    .from("Ordens_Servico")
    .select("*")
    .eq("orderNumber", orderNumber)
    .single();

  if (error || !os) return res.status(404).json({ error: "OS não encontrada" });

  if (os.status !== "Aguardando verificação PCP") {
    return res.status(400).json({ error: "Não há produção pendente para validar" });
  }

  let atualizacoes = {};

  if (aprovado) {
    // Descobre o próximo setor no roteiro
    const rota = os.routing;
    const indexAtual = rota.findIndex(r => r.sector === os.pendingSector);
    const proximo = rota[indexAtual + 1];

    atualizacoes = {
      status: proximo ? "Em andamento" : "Finalizado",
      currentSector: proximo || null,
      pendingSector: null,
    };
  } else {
    atualizacoes = {
      status: "Reprovado pelo PCP",
    };
  }

  const { data: updated, error: updateError } = await supabase
    .from("Ordens_Servico")
    .update(atualizacoes)
    .eq("orderNumber", orderNumber)
    .select("*")
    .single();

  if (updateError) return res.status(500).json({ error: updateError.message });

  res.json({
    message: `Produção validada pelo PCP. ${aprovado ? "Avançando para próximo setor" : "Reprovada"}.`,
    os: updated,
  });
});


app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
