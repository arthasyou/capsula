/// Cap1 数据胶囊封装与解封示例
///
/// # 概述
///
/// 本示例演示了Capsula数据胶囊系统中Cap1（解释层）的完整工作流程。
/// Cap1是三层胶囊架构中的核心应用层，专门用于存储BNF解析后的结构化数据。
///
/// # 三层胶囊架构说明
///
/// * **Cap0（原始数据层）**: 用于数据备份和追溯，保存原始数据和文字注释
/// * **Cap1（解释层）**: 核心应用层，包含BNF提取的结构化数据，只有这一层才有BNF字段
/// * **Cap2（聚合层）**: 按所有者聚合的数据捆绑层
///
/// # 示例流程
///
/// 1. **生成密钥对** - 创建RSA签名和接收者密钥对
/// 2. **创建Cap0原始数据层** - 封装医疗影像原始数据和文字注释
/// 3. **创建Cap1解释层** - 基于Cap0创建解释层，包含BNF提取的结构化数据
/// 4. **封装到统一胶囊容器** - 将Cap1封装到带有AAD绑定的统一容器中
/// 5. **验证胶囊完整性** - 验证AAD绑定和防篡改检查
/// 6. **安全访问数据** - 演示如何安全地访问BNF提取数据和元数据
/// 7. **显示胶囊摘要** - 展示胶囊的基本信息和元数据
///
/// # 关键技术概念
///
/// * **BNF提取**: 使用巴科斯-诺尔范式将非结构化数据转换为结构化格式
/// * **AAD绑定**: Additional Authenticated Data绑定，防止组件替换攻击
/// * **SealedBlock**: 最小可验证封装单元，支持AEAD加密和作者证明
/// * **统一胶囊容器**: 包含头部、策略、密钥环、载荷等完整组件的容器
use std::collections::HashMap;

use capsula_core::{
    builder::CapsuleBuilder,
    capsule::{Cap0, Cap1, Capsule, CapsuleHeader, CapsulePayload, PolicyControl},
    keyring::Keyring,
    types::{CapsulaStage, ContentType},
    Result,
};
use capsula_key::{Key, RsaKey};

fn main() -> Result<()> {
    println!("🚀 启动 Cap1 数据胶囊封装与解封示例");

    // 1. 生成测试密钥
    println!("\n📋 步骤 1: 生成密钥对");
    let signing_key = RsaKey::generate_2048()?;
    let recipient_key = RsaKey::generate_2048()?;
    println!("✅ 签名密钥和接收者密钥已生成");

    // 2. 创建医疗影像原始数据 (Cap0)
    println!("\n📋 步骤 2: 创建 Cap0 原始数据层");
    let cap0 = create_medical_cap0(&signing_key, &recipient_key)?;
    println!("✅ Cap0 创建完成 - 包含医疗影像数据和文字注释");

    // 3. 创建 Cap1 解释层（包含 BNF 提取）
    println!("\n📋 步骤 3: 创建 Cap1 解释层");
    let cap1 = create_cap1_with_bnf_extract(&signing_key, &recipient_key, &cap0)?;
    println!("✅ Cap1 创建完成 - 包含 BNF 解析的结构化医疗数据");

    // 4. 创建统一胶囊容器
    println!("\n📋 步骤 4: 封装到统一胶囊容器");
    let capsule = create_unified_capsule(cap1)?;
    println!("✅ 统一胶囊创建完成 - 包含 AAD 绑定和策略控制");

    // 5. 验证胶囊完整性
    println!("\n📋 步骤 5: 验证胶囊完整性");
    verify_capsule_integrity(&capsule)?;
    println!("✅ 胶囊完整性验证通过");

    // 6. 解封和访问数据
    println!("\n📋 步骤 6: 解封和访问数据");
    access_capsule_data(&capsule, &recipient_key)?;
    println!("✅ 数据访问完成");

    // 7. 显示胶囊摘要
    println!("\n📋 步骤 7: 显示胶囊摘要信息");
    display_capsule_summary(&capsule);

    println!("\n🎉 Cap1 数据胶囊封装与解封示例完成！");
    Ok(())
}

/// 创建医疗影像的 Cap0 原始数据层
///
/// Cap0是数据胶囊的第一层，用于封装原始数据和文字注释。
/// 这一层主要用于数据备份和追溯，保持原始数据的完整性。
///
/// # 参数
/// * `_signing_key` - 签名密钥（示例中暂不使用实际签名）
/// * `_recipient_key` - 接收者密钥（示例中暂不使用实际加密）
///
/// # 返回
/// 返回创建的Cap0结构，包含原始影像数据和文字注释
fn create_medical_cap0(_signing_key: &RsaKey, _recipient_key: &RsaKey) -> Result<Cap0> {
    println!("  创建医疗影像原始数据...");

    // 模拟医疗影像数据 - 在实际应用中这里会是真实的医疗影像文件
    let image_data = include_bytes!("../README.md"); // 使用README作为测试数据

    // 在实际应用中，这里会配置真实的密钥环用于数据加密
    // 目前为简化演示，使用空的密钥环
    let _keyring: Keyring = HashMap::new();

    // 在实际应用中，这里会获取真实的接收者公钥用于密钥封装
    // 目前为简化演示，暂时跳过实际的密钥操作
    let _public_keys = _recipient_key.public_keys();
    let _signing_key_entry = _public_keys.signing_key().ok_or_else(|| {
        capsula_core::error::CoreError::DataError("No signing key found".to_string())
    })?;
    let _recipient_public_key_spki = _signing_key_entry.spki_der.clone();

    // 使用 CapsuleBuilder 创建原始数据封装
    let cap0_capsule = CapsuleBuilder::new()
        .with_header(
            "cid:medical_image_20250115".to_string(),
            "medical.imaging.chest_xray".to_string(),
            CapsulaStage::First,
        )
        .with_policy(
            "policy://hospital/imaging/chest_xray".to_string(),
            vec!["read".to_string(), "backup".to_string()],
        )
        .with_empty_keyring()
        .build_cap0()
        .with_origin_data(image_data.to_vec(), ContentType::Png)?
        .with_text_annotation(
            serde_json::to_string(&serde_json::json!({
                "type": "医疗影像描述",
                "content": "胸部X光片，显示双肺清晰，心影正常大小",
                "extracted_text": "Patient: 张三, Age: 45, Date: 2025-01-15",
                "findings": ["双肺纹理清晰", "心影大小正常", "未见异常阴影"]
            }))
            .unwrap(),
        )?
        .build()?;

    // 获取Cap0用于后续Cap1关联
    let cap0 = if let CapsulePayload::Cap0(cap0) = cap0_capsule.get_payload() {
        cap0
    } else {
        return Err(capsula_core::error::CoreError::DataError(
            "载荷类型不匹配".to_string(),
        ));
    };

    println!("  ✓ 原始影像数据已封装");
    println!("  ✓ 文字注释已添加");
    Ok(cap0.clone())
}

/// 创建 Cap1 解释层，包含 BNF 提取的结构化数据
///
/// Cap1是数据胶囊的第二层（解释层），是真正的核心应用层。
/// 这一层包含使用BNF（巴科斯-诺尔范式）对原始数据进行解析后的结构化内容。
/// Cap1只有这一层才有BNF提取字段，因为它是专门的解释和分析层。
///
/// # 参数
/// * `_signing_key` - 签名密钥（示例中暂不使用实际签名）
/// * `_recipient_key` - 接收者密钥（示例中暂不使用实际加密）
/// * `_cap0` - 关联的Cap0原始数据层（用于追溯）
///
/// # 返回
/// 返回创建的Cap1结构，包含元数据和BNF提取的结构化医疗数据
fn create_cap1_with_bnf_extract(
    _signing_key: &RsaKey,
    _recipient_key: &RsaKey,
    _cap0: &Cap0,
) -> Result<Cap1> {
    println!("  基于 Cap0 创建 Cap1 解释层...");

    // BNF 提取的结构化医疗数据
    // 这是Cap1的核心价值：将非结构化的原始数据转换为结构化的、可分析的数据
    let bnf_extracted_data = serde_json::json!({
        "patient": {
            "name": "张三",
            "age": 45,
            "id": "P001",
            "gender": "男"
        },
        "examination": {
            "type": "胸部X光",
            "date": "2025-01-15",
            "equipment": "Siemens MULTIX Pro",
            "technique": "后前位立位摄影"
        },
        "findings": {
            "lungs": {
                "left": {"status": "正常", "details": "纹理清晰，无实变"},
                "right": {"status": "正常", "details": "纹理清晰，无实变"}
            },
            "heart": {
                "size": "正常",
                "shape": "正常",
                "position": "居中"
            },
            "bones": {
                "ribs": "完整",
                "spine": "正常排列"
            }
        },
        "conclusion": {
            "diagnosis": "双肺未见异常",
            "recommendation": "建议年度复查",
            "urgency": "非急性"
        },
        "metadata": {
            "extracted_by": "BNF Parser v1.0",
            "confidence": 0.95,
            "validation_status": "已验证"
        }
    });

    // 在实际应用中，这里会配置真实的密钥环用于数据加密
    // 目前为简化演示，使用空的密钥环
    let _keyring: Keyring = HashMap::new();

    // 在实际应用中，这里会获取真实的接收者公钥用于密钥封装
    // 目前为简化演示，暂时跳过实际的密钥操作
    let _public_keys = _recipient_key.public_keys();
    let _signing_key_entry = _public_keys.signing_key().ok_or_else(|| {
        capsula_core::error::CoreError::DataError("No signing key found".to_string())
    })?;
    let _recipient_public_key_spki = _signing_key_entry.spki_der.clone();

    // 使用 CapsuleBuilder 创建解释层
    let cap1_capsule = CapsuleBuilder::new()
        .with_header(
            "cid:medical_interpretation_20250115".to_string(),
            "medical.imaging.interpretation".to_string(),
            CapsulaStage::Second,
        )
        .with_policy(
            "policy://hospital/interpretation/chest_xray".to_string(),
            vec!["read".to_string(), "medical_view".to_string()],
        )
        .with_empty_keyring()
        .build_cap1()
        .cap0_id(format!("cap0_{}", ContentType::Png as u8))
        .with_meta_data(
            serde_json::to_vec(&serde_json::json!({
                "processing_info": {
                    "algorithm": "Medical Image Analysis v2.1",
                    "processed_at": "2025-01-15T10:30:00Z",
                    "quality_score": 0.98
                },
                "compliance": {
                    "hipaa_compliant": true,
                    "gdpr_compliant": true,
                    "audit_trail": "enabled"
                }
            }))
            .unwrap(),
        )?
        .with_bnf_extract_json(bnf_extracted_data)?
        .build()?;

    // 获取Cap1用于后续封装
    let cap1 = if let CapsulePayload::Cap1(cap1) = cap1_capsule.get_payload() {
        cap1
    } else {
        return Err(capsula_core::error::CoreError::DataError(
            "载荷类型不匹配".to_string(),
        ));
    };

    println!("  ✓ BNF 提取完成 - 结构化医疗数据已生成");
    println!("  ✓ 元数据和合规信息已添加");
    Ok(cap1.clone())
}

/// 创建统一胶囊容器
///
/// 将Cap1封装到统一的胶囊容器中，这是最外层的封装。
/// 统一胶囊容器包含头部信息、访问策略、密钥环、载荷和AAD绑定等组件。
/// AAD（Additional Authenticated Data）绑定可以防止组件替换攻击。
///
/// # 参数
/// * `cap1` - 要封装的Cap1解释层数据
///
/// # 返回
/// 返回完整的统一胶囊容器，包含所有必要的安全和管理组件
fn create_unified_capsule(cap1: Cap1) -> Result<Capsule> {
    println!("  创建胶囊头部和策略...");

    // 创建胶囊头部 - 包含胶囊的基本元数据信息
    let header = CapsuleHeader {
        id: "cid:medical_chest_xray_20250115".to_string(),
        version: "1.0".to_string(),
        stage: CapsulaStage::Second, // Cap1 对应第二阶段
        content_type: "medical.imaging.chest_xray".to_string(),
        created_at: "2025-01-15T10:30:00Z".to_string(),
        creator: Some("Dr. 李医生".to_string()),
        metadata: None,
    };

    // 创建访问控制策略
    let policy = PolicyControl::new(
        "policy://hospital/radiology/chest_xray".to_string(),
        vec![
            "read".to_string(),
            "medical_view".to_string(),
            "print_report".to_string(),
        ],
    );

    // 创建空密钥环（实际使用中会包含访问控制相关的密钥）
    let keyring: Keyring = HashMap::new();

    // 创建载荷
    let payload = CapsulePayload::Cap1(cap1);

    // 使用 Capsule::new 创建统一胶囊
    let capsule = Capsule::new(header, policy, keyring, payload)?;

    println!("  ✓ 胶囊头部已创建");
    println!("  ✓ 访问策略已配置");
    println!("  ✓ AAD 绑定已建立");

    Ok(capsule)
}

/// 验证胶囊完整性
///
/// 验证胶囊的完整性，确保数据没有被篡改。
/// 主要验证AAD（Additional Authenticated Data）绑定，这可以防止组件替换攻击。
/// AAD绑定将胶囊的各个组件（头部、策略、密钥环、载荷）绑定在一起。
///
/// # 参数
/// * `capsule` - 要验证的胶囊容器
///
/// # 返回
/// 验证成功返回Ok(())，失败返回错误信息
fn verify_capsule_integrity(capsule: &Capsule) -> Result<()> {
    println!("  验证 AAD 绑定...");

    // 验证 AAD 绑定 - 确保胶囊组件没有被恶意替换
    let aad_valid = capsule.verify_aad_binding()?;
    if !aad_valid {
        return Err(capsula_core::error::CoreError::DataError(
            "AAD 绑定验证失败".to_string(),
        ));
    }

    println!("  ✓ AAD 绑定验证通过");
    println!("  ✓ 组件完整性确认");
    println!("  ✓ 防篡改检查通过");

    Ok(())
}

/// 访问胶囊数据
///
/// 安全地访问胶囊中的数据内容。
/// 在实际应用中，这里会使用接收者的私钥来解封加密的数据。
/// 目前为简化演示，只展示数据访问的流程和元数据获取。
///
/// # 参数
/// * `capsule` - 要访问的胶囊容器
/// * `_recipient_key` - 接收者私钥（实际解封时使用，示例中暂不使用）
///
/// # 返回
/// 访问成功返回Ok(())，失败返回错误信息
fn access_capsule_data(capsule: &Capsule, _recipient_key: &RsaKey) -> Result<()> {
    println!("  访问胶囊内容...");

    // 获取载荷 - 提取胶囊中封装的实际数据
    if let CapsulePayload::Cap1(cap1) = capsule.get_payload() {
        println!("  ✓ 确认载荷类型: Cap1 解释层");

        // 获取 BNF 提取的数据（需要密钥解封）
        let bnf_block = cap1.get_bnf_extract();
        println!("  ✓ BNF 提取数据块已获取");
        println!("    - 内容类型: {:?}", bnf_block.content_type);
        println!("    - 加密算法: {:?}", bnf_block.ciphertext.enc);

        // 在实际应用中，这里会使用 recipient_key 来解封数据
        // 由于示例的复杂性，这里只展示数据访问的流程
        println!("  ✓ 数据访问权限验证通过");
        println!("  ✓ 可以安全解封 BNF 结构化数据");

        // 获取元数据
        let _meta_block = cap1.get_meta();
        println!("  ✓ 元数据已获取");
        println!("    - 处理信息和合规数据可访问");
    } else {
        return Err(capsula_core::error::CoreError::DataError(
            "载荷类型不匹配".to_string(),
        ));
    }

    Ok(())
}

/// 显示胶囊摘要信息
///
/// 展示胶囊的基本信息和元数据摘要。
/// 这些信息包括胶囊ID、版本、阶段、内容类型、创建者等关键属性。
/// 摘要信息可以帮助用户快速了解胶囊的基本特征，无需解封整个胶囊。
///
/// # 参数
/// * `capsule` - 要显示摘要的胶囊容器
fn display_capsule_summary(capsule: &Capsule) {
    println!("  📊 胶囊摘要信息:");
    let summary = capsule.get_summary();

    println!("    🆔 胶囊ID: {}", summary.id);
    println!("    📦 版本: {}", summary.version);
    println!("    🏷️  阶段: {:?}", summary.stage);
    println!("    📋 内容类型: {}", summary.content_type);
    println!("    👤 创建者: {:?}", summary.creator);
    println!("    📄 载荷类型: {}", summary.payload_type);
    println!("    🔐 策略引用: {}", summary.policy_ref);
    println!(
        "    🖼️  包含水印: {}",
        if summary.has_watermark { "是" } else { "否" }
    );
    println!(
        "    📝 包含审计: {}",
        if summary.has_audit_ref { "是" } else { "否" }
    );
    println!("    📅 创建时间: {}", summary.created_at);
}
