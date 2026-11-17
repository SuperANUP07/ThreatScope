package com.threatscope.threatscope.rule;

import com.threatscope.threatscope.model.Alert;
import java.util.List;

public interface DetectionRule {
    String name();
    List<Alert> evaluate();
}