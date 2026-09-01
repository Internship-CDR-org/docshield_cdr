package model.pptx;

import java.util.ArrayList;
import java.util.List;

public class PPTXLayout {

    private int index;
    private String name;

    private final List<PPTXLayoutElement> elements =
            new ArrayList<>();

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<PPTXLayoutElement> getElements() {
        return elements;
    }

    public void addElement(PPTXLayoutElement element) {
        elements.add(element);
    }
}